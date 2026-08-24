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

    /// Design width. On a compact screen this IS the rendered width
    /// (the table scrolls horizontally); on a regular-width screen
    /// (iPad, landscape) the columns stretch past it, and these
    /// values then act purely as the RATIO in which the surplus is
    /// divided - see `widthFraction`.
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

    /// Combined width of the 1pt dividers between adjacent columns.
    /// Subtracted before the columns split the row, so the fractions
    /// below always add up to the row width exactly.
    static let separatorTotal = CGFloat(max(allCases.count - 1, 0))

    /// Sum of the design widths, EXCLUDING separators.
    static let designWidth: CGFloat = allCases.reduce(0) { $0 + $1.width }

    /// Share of the row (minus separators) this column takes. Summing
    /// this over `allCases` gives exactly 1, which is what lets the
    /// table fill any width without leaving a gap at the trailing
    /// edge or overflowing the card.
    var widthFraction: CGFloat { width / TokenColumn.designWidth }
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
    fileprivate static let totalColumnsWidth: CGFloat =
    TokenColumn.designWidth + TokenColumn.separatorTotal
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
    /// Two-tab segmented control replacing the previous "Tokens"
    /// section title. The first tab shows tokens whose contract is
    /// in `RecognizedTokens.all`; the second tab shows the rest of
    /// the post-impersonator-filter list. The control sits in the
    /// same screen position the title used to occupy, and is
    /// hidden together with the card when both partitions are
    /// empty (see `applyEmptyState()`). This is the anti-impersonation
    /// surface that lets the user see at a glance whether a token
    /// row is vendor-vouched (recognized) or strictly indexer-
    /// derived (unrecognized).
    private let tokensSegmentedControl: UISegmentedControl = {
        let L = Localization.shared
        return UISegmentedControl(items: [
            L.getTokensTabByLangValues(),
            L.getUnrecognizedTokensTabByLangValues()
        ])
    }()

    /// Tab buckets enumerated as their backing index in
    /// `tokensSegmentedControl` so a single accessor maps tab ->
    /// data source slice without shadowing `selectedSegmentIndex`.
    private enum TokensTab: Int { case recognized = 0, unrecognized = 1 }

    /// Raw items from the scan API (post-impersonator-filter). The
    /// table never reads this directly; it always reads through
    /// `displayedItems` so the tab selection is the single source
    /// of truth at render time.
    private var items: [AccountTokenSummary] = []
    /// Recognized partition derived once per `applyFilteredItems`
    /// pass so cellForRowAt does not re-filter on every scroll
    /// callback.
    private var recognizedItems: [AccountTokenSummary] = []
    /// Unrecognized partition (everything in `items` that did NOT
    /// land in `recognizedItems`).
    private var unrecognizedItems: [AccountTokenSummary] = []
    private var nextPage = 1
    private var loading = false
    private var currentAddress: String { resolveCurrentAddress() }

    /// Snapshot of the partition slice that the table data source
    /// reads. MUST always be updated in lockstep with
    /// `table.reloadData()` via `reloadDisplayedItems()` so that
    /// `numberOfRowsInSection` and `cellForRowAt` cannot disagree.
    ///
    /// Why a stored snapshot (not a computed property reading
    /// `recognizedItems` / `unrecognizedItems` live):
    ///   `cellForRowAt` is sometimes called by UIKit AFTER
    ///   `numberOfRowsInSection` returned a now-stale higher count -
    ///   a UISegmentedControl `.valueChanged` action that fires
    ///   inside a touch event's layout pass, a `reloadData()` from
    ///   a NotificationCenter callback that races a previously
    ///   scheduled layout, or a `loadNextPage` completion that
    ///   mutates the partition arrays mid-render. With a computed
    ///   `displayedItems`, those races read the NEW partition
    ///   under an OLD index and crash with `Index out of range`.
    ///   The snapshot is mutated only by `reloadDisplayedItems()`,
    ///   which always pairs the assignment with `table.reloadData()`
    ///   so any subsequent layout pass (even one queued before the
    ///   call) sees a consistent (count, slice) pair.
    private var displayedItems: [AccountTokenSummary] = []

    /// Single chokepoint that refreshes the `displayedItems`
    /// snapshot from the current tab + the current partition, then
    /// asks the table to reload. Every call site that previously
    /// invoked `table.reloadData()` directly should call this
    /// instead so the snapshot can never lag behind the visible
    /// table state.
    private func reloadDisplayedItems() {
        switch TokensTab(rawValue: tokensSegmentedControl.selectedSegmentIndex)
            ?? .recognized {
            case .recognized:
            displayedItems = recognizedItems
            case .unrecognized:
            displayedItems = unrecognizedItems
        }
        table.reloadData()
    }

    /// Monotonically increasing generation token bumped on every
    /// network switch. Each pagination fetch captures the value at
    /// start; on response we apply the result only when the
    /// captured generation still matches the current one. Without
    /// this, a fetch already in flight against the OLD network's
    /// scan API would land AFTER the network change cleared
    /// `items` and would re-populate the table with stale tokens
    /// from the previous chain - the user-visible "tokens table
    /// did not refresh after I switched networks" symptom. The
    /// counter is also what lets `handleNetworkConfigDidChange`
    /// drop the `loading` guard safely: even if the prior fetch is
    /// still in flight, its response is discarded, so a fresh page
    /// 1 fetch against the new network can start immediately.
    private var fetchGeneration: UInt64 = 0

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
        // Two-tab segmented control sits OUTSIDE the
        // horizontally-scrollable card so it stays put when the user
        // pans through the column strip. The selected tab drives
        // `displayedItems`, which the table data source reads
        // directly; switching tabs simply triggers `reloadData`.
        tokensSegmentedControl.translatesAutoresizingMaskIntoConstraints = false
        tokensSegmentedControl.selectedSegmentIndex = TokensTab.recognized.rawValue
        tokensSegmentedControl.addTarget(self, action: #selector(changeTokenTab),
            for: .valueChanged)
        view.addSubview(tokensSegmentedControl)

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
        // Pull-to-refresh on the post-unlock home wallet. Drags down
        // on the token table re-fetches page 1 without clearing the
        // visible rows and posts `walletHomeRefreshRequested` so the
        // HomeViewController can also reissue its balance fetch. The
        // standard UIRefreshControl spinner is sufficient feedback
        // here - Android does the same `SwipeRefreshLayout` pattern.
        let rc = UIRefreshControl()
        rc.addTarget(self, action: #selector(handlePullToRefresh), for: .valueChanged)
        table.refreshControl = rc
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

        // Pulls the column container back down to the design width
        // once both required minimums above are satisfied. Must sit
        // below `.required` so it can yield to whichever minimum is
        // larger; without it the container would be free to grow
        // without bound.
        let shrinkToFit = columnContainer.widthAnchor.constraint(
            equalToConstant: Self.totalColumnsWidth)
        shrinkToFit.priority = .defaultHigh

        NSLayoutConstraint.activate([
                // Segmented control pinned to the top of the view,
                // inset by the same `cardInset` that frames the card
                // below so the control sits flush with the card's
                // leading edge. Sits in the same vertical position
                // the previous "Tokens" title used to occupy.
                tokensSegmentedControl.topAnchor.constraint(equalTo: view.topAnchor, constant: 4),
                tokensSegmentedControl.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: Self.cardInset),
                tokensSegmentedControl.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -Self.cardInset),

                // Horizontal scroller is inset on bottom + leading +
                // trailing by `cardInset` so the rounded card border is
                // visible on every edge. Top sits 8pt below the
                // segmented control so the card chrome reads as a
                // labelled section rather than a floating panel. The
                // trailing inset also doubles as the gutter for the
                // custom vertical scroll indicator.
                horizontalScrollView.topAnchor.constraint(equalTo: tokensSegmentedControl.bottomAnchor, constant: 8),
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

                // Column container drives `contentSize.width` and pins
                // to the card's edges so the inner header / table sit
                // flush inside the rounded shell. Its width is
                // max(design width, visible width): the two required
                // minimums below set the floor, and the high-priority
                // equality pulls the width down to whichever floor is
                // higher. On a phone the design width wins and the
                // table scrolls horizontally as before; on iPad (and
                // landscape) the visible width wins, so the card fills
                // the screen instead of stopping at 743pt with dead
                // space to its right.
                columnContainer.topAnchor.constraint(equalTo: card.topAnchor),
                columnContainer.bottomAnchor.constraint(equalTo: card.bottomAnchor),
                columnContainer.leadingAnchor.constraint(equalTo: card.leadingAnchor),
                columnContainer.trailingAnchor.constraint(equalTo: card.trailingAnchor),
                columnContainer.widthAnchor.constraint(
                    greaterThanOrEqualToConstant: Self.totalColumnsWidth),
                columnContainer.widthAnchor.constraint(
                    greaterThanOrEqualTo: horizontalScrollView.frameLayoutGuide.widthAnchor),
                shrinkToFit,

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
        // Bump the generation FIRST so any in-flight page fetch
        // against the old network's scan API silently drops its
        // result on return (see `loadNextPage` and the
        // `fetchGeneration` doc). Then clear local state and
        // reset `loading` so the immediate `loadNextPage` below
        // is allowed to run even if the prior request hasn't
        // completed - without this reset the new fetch would be
        // suppressed by the `guard !loading` check and the
        // user would either see the table stay empty or, worse,
        // the now-stale prior fetch would land after the clear
        // and re-populate the table with the previous network's
        // tokens.
        fetchGeneration &+= 1
        items = []
        recognizedItems = []
        unrecognizedItems = []
        nextPage = 1
        loading = false
        // Reset the tab back to "Recognized" on every network
        // switch: the new chain might not have any unrecognized
        // tokens at all, and leaving the user on the empty
        // "Unrecognized Tokens" tab after a switch would look like
        // a bug.
        tokensSegmentedControl.selectedSegmentIndex = TokensTab.recognized.rawValue
        reloadDisplayedItems()
        applyEmptyState()
        loadNextPage()
    }

    /// Hide the entire token-table card AND the segmented tab
    /// control whenever the post-impersonator-filter token list is
    /// empty (i.e. no recognized AND no unrecognized rows to
    /// show). Without this, an empty rounded card with just the
    /// column-header row, plus a stranded segmented control above
    /// it, would linger on the home screen even when there is
    /// nothing to list - a confusing "broken UI" affordance.
    /// Toggled instead of removed from the view hierarchy so the
    /// layout stays stable across reloads / network switches.
    private func applyEmptyState() {
        let isEmpty = recognizedItems.isEmpty && unrecognizedItems.isEmpty
        tokensSegmentedControl.isHidden = isEmpty
        horizontalScrollView.isHidden = isEmpty
        scrollIndicator.isHidden = isEmpty
    }

    /// Tab change handler. Just swaps which partition the data
    /// source returns; the scan-API state and pagination cursor
    /// are unaffected. The empty-state surface is also a no-op
    /// here because the segmented control is only visible if at
    /// least one of the two partitions is non-empty.
    @objc private func changeTokenTab() {
        reloadDisplayedItems()
    }

    /// Single chokepoint that recomputes `recognizedItems` and
    /// `unrecognizedItems` from `items`. Called after every
    /// pagination append and on the initial load. Held as a
    /// dedicated method so test fixtures and any future call
    /// sites (e.g. a manual refresh button) can re-partition
    /// without going through `loadNextPage`.
    private func applyFilteredItems() {
        recognizedItems = items.filter {
            RecognizedTokens.isRecognized($0.contractAddress)
        }
        unrecognizedItems = items.filter {
            !RecognizedTokens.isRecognized($0.contractAddress)
        }
    }

    /// Pull-to-refresh handler attached to `table.refreshControl`.
    /// Re-fetches page 1 of the token list WITHOUT clearing the
    /// currently-visible rows: the new page replaces `items`
    /// atomically on success, but on failure the user keeps seeing
    /// the previous list (matches the Android refresh-error UX).
    /// Also posts `walletHomeRefreshRequested` so the
    /// `HomeViewController` re-issues the native balance fetch -
    /// kept decoupled via NotificationCenter so this controller does
    /// not have to walk the parent chain.
    @objc private func handlePullToRefresh() {
        if ScanApiRateLimiter.shared.isThrottled() {
            table.refreshControl?.endRefreshing()
            NotificationCenter.default.post(
                name: .scanApiRateLimitNotifyUser, object: nil)
            return
        }
        NotificationCenter.default.post(
            name: .walletHomeRefreshRequested, object: nil)
        loadFirstPage(replacing: true, manual: true)
    }

    /// Page-1 fetch variant used by pull-to-refresh. Increments
    /// `fetchGeneration` so any in-flight pagination request is
    /// dropped on return, swaps the visible items atomically on
    /// success, and on failure leaves the previously-displayed list
    /// alone. `manual == true` opts in to a dismissible error
    /// dialog; auto-driven callers leave it false and stay silent.
    private func loadFirstPage(replacing: Bool, manual: Bool) {
        let address = currentAddress
        guard !address.isEmpty else {
            table.refreshControl?.endRefreshing()
            return
        }
        fetchGeneration &+= 1
        let generationAtFetch = fetchGeneration
        // Cancel the in-flight `loading` guard so the auto-paginator
        // does not block the manual refresh; the generation check
        // below still discards the older request's response.
        loading = true
        Task { @MainActor in
            await Task.yield()
            defer {
                self.table.refreshControl?.endRefreshing()
                if generationAtFetch == self.fetchGeneration {
                    self.loading = false
                }
            }

            if ScanApiRateLimiter.shared.isThrottled() {
                if manual {
                    NotificationCenter.default.post(
                        name: .scanApiRateLimitNotifyUser, object: nil)
                }
                return
            }

            let result: AccountTokenListResponse?
            let caughtError: Error?
            do {
                result = try await AccountsApi.accountTokens(
                    address: address, pageIndex: 1)
                caughtError = nil
            } catch {
                result = nil
                caughtError = error
            }

            guard generationAtFetch == self.fetchGeneration else { return }
            guard let resp = result else {
                if manual, let err = caughtError {
                    let message: String
                    if let api = err as? ApiError {
                        if case .http(let status, let body) = api, status == 429 {
                            message = ApiError.rateLimitUserMessage(detail: body)
                        } else {
                            message = api.description
                        }
                    } else {
                        message = "\(err)"
                    }
                    let dlg = MessageInformationDialogViewController.error(
                        title: Localization.shared.getErrorTitleByLangValues(),
                        message: message)
                    self.present(dlg, animated: true)
                }
                return
            }
            let raw = resp.result ?? []
            let filtered = StablecoinImpersonatorFilter.filter(raw)
            if replacing {
                self.items = filtered
                self.nextPage = 2
            } else {
                self.items.append(contentsOf: filtered)
                self.nextPage += 1
            }
            self.applyFilteredItems()
            self.reloadDisplayedItems()
            self.applyEmptyState()
        }
    }

    private func loadNextPage() {
        guard !loading else { return }
        let address = currentAddress
        guard !address.isEmpty else { return }
        loading = true
        // Capture the generation at fetch start. The completion
        // handler below applies the response only when this token
        // still matches the live `fetchGeneration`; a network
        // switch (or any future invalidation event that bumps the
        // counter) between dispatch and response causes the result
        // to be dropped on the floor instead of leaking the
        // previous network's tokens into the post-switch table.
        // The `loading` reset is also gated by the generation:
        // if the network was switched while this fetch was in
        // flight, `handleNetworkConfigDidChange` already cleared
        // `loading` and started a fresh fetch, so we must NOT
        // overwrite that fresh fetch's `loading=true` state.
        let generationAtFetch = fetchGeneration
        Task { [nextPage] in
            let result = try? await AccountsApi.accountTokens(
                address: address, pageIndex: nextPage)
            await MainActor.run {
                guard generationAtFetch == self.fetchGeneration else { return }
                self.loading = false
                guard let resp = result else {
                    // Silent on error: Android
                    // `HomeMainFragment.refreshTokenList` mirrors
                    // this. The home path's automatic-error UX
                    // is driven by the balance fetch
                    // (HomeViewController), which hides the
                    // token table on failure; manual refresh
                    // surfaces a dialog. Pagination errors here
                    // simply don't extend the list.
                    return
                }
                // Pre-filter at the SINGLE chokepoint so
                // stablecoin-impersonator tokens never reach
                // either tab. Recognized contracts are
                // explicitly let through inside the filter even
                // when their name happens to match a pattern -
                // see `StablecoinImpersonatorFilter`.
                let raw = resp.result ?? []
                let filtered = StablecoinImpersonatorFilter.filter(raw)
                self.items.append(contentsOf: filtered)
                self.applyFilteredItems()
                self.reloadDisplayedItems()
                self.applyEmptyState()
                self.nextPage += 1
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
        // Built through the same assembler the rows use, so the
        // sticky header's dividers and column widths cannot drift
        // out of alignment with the cells scrolling beneath it.
        TokenCell.layOutColumns(TokenColumn.allCases.map(makeHeaderCell(for:)), in: stack)

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

    /// Single header column: a container around a label taking the
    /// same share of the row as the matching `TokenCell` column, so
    /// header and rows stay aligned at every width.
    private func makeHeaderCell(for col: TokenColumn) -> UIView {
        let label = UILabel()
        label.text = col.title
        label.font = Typography.mediumLabel(13)
        label.textColor = .secondaryLabel
        label.textAlignment = col.alignment
        return TokenCell.wrapColumn(label)
    }

    // MARK: - UITableViewDataSource / Delegate

    public func tableView(_ tv: UITableView, numberOfRowsInSection section: Int) -> Int {
        displayedItems.count
    }

    public func tableView(_ tv: UITableView, cellForRowAt ip: IndexPath) -> UITableViewCell {
        let cell = tv.dequeueReusableCell(withIdentifier: "token", for: ip) as! TokenCell
        // Defensive bounds check: `reloadDisplayedItems()` is the
        // single chokepoint that keeps `displayedItems.count`
        // in lockstep with the table's committed row count, but
        // UIKit can ask for cells from a previously committed
        // row count during in-flight layout passes (a tab-switch
        // touch event, a NotificationCenter-driven reload, or
        // an animation that races `reloadData()`). Returning a
        // blank cell in that window is far less harmful than
        // crashing the home screen.
        guard ip.row >= 0, ip.row < displayedItems.count else { return cell }
        cell.configure(displayedItems[ip.row])
        return cell
    }

    public func tableView(_ tv: UITableView, willDisplay cell: UITableViewCell, forRowAt ip: IndexPath) {
        // Pagination cursor is global (the scan API returns rows
        // we must split into the two tabs after the fact), so
        // measure remaining rows against the FULL `items` list -
        // not the per-tab `displayedItems` slice. Without this,
        // switching to a partition with very few rows would stop
        // pagination prematurely on the other tab.
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
            Self.wrapColumn(symbolButton, verticalInset: 8),
            Self.wrapColumn(balanceLabel, verticalInset: 8),
            Self.wrapColumn(nameLabel, verticalInset: 8),
            Self.wrapColumn(contractButton, verticalInset: 8)
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
        Self.layOutColumns(wrapped, in: row)
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

    /// Assembles one table row - header or cell - from `columns` in
    /// `TokenColumn.allCases` order: 1pt dividers interleaved
    /// between adjacent columns (never on the outside; the card
    /// border supplies those edges), then each column sized to its
    /// share of the stack.
    ///
    /// The width is a FRACTION of the stack rather than a constant,
    /// so the columns divide whatever width the row actually got:
    /// the design width on a phone, the full screen width on iPad.
    /// The `-separatorTotal * fraction` term hands each column its
    /// share of the space the dividers occupy, which is what makes
    /// the fractions add up to the row width exactly.
    ///
    /// Widths are applied only AFTER every column is an arranged
    /// subview: a constraint between a column and the stack is
    /// illegal (and throws) while the two have no common ancestor.
    static func layOutColumns(_ columns: [UIView], in stack: UIStackView) {
        assert(columns.count == TokenColumn.allCases.count,
            "Row must supply exactly one view per TokenColumn.")
        for (idx, column) in columns.enumerated() {
            if idx > 0 { stack.addArrangedSubview(makeColumnSeparator()) }
            stack.addArrangedSubview(column)
        }
        for (view, col) in zip(columns, TokenColumn.allCases) {
            let fraction = col.widthFraction
            let width = view.widthAnchor.constraint(
                equalTo: stack.widthAnchor,
                multiplier: fraction,
                constant: -TokenColumn.separatorTotal * fraction)
            // One notch below `.required`: the four fractions sum to
            // 1 in exact arithmetic but can land a hair off in
            // floating point, and a `.fill` stack pins its first and
            // last arranged subview to its own edges with required
            // priority. Yielding by that hair beats logging a broken
            // constraint.
            width.priority = .required - 1
            width.isActive = true
        }
    }

    /// Column wrapper used by both this cell and the
    /// `HomeMainViewController` header, holding a label / button
    /// with a small visual gap on either side. Exposed `static`
    /// because the header builds wrappers independently of any row
    /// instance. The wrapper is deliberately width-less here -
    /// `layOutColumns` assigns the width once the wrapper is inside
    /// its stack, because the width is relative to that stack.
    ///
    /// `verticalInset` lets cell call sites carve out the 8pt
    /// breathing room around labels INSIDE the wrapper (so the
    /// wrapper itself - and therefore the sibling column-separator
    /// view in the same `.fill`-aligned stack - reaches edge-to-
    /// edge of the row). Header call sites pass the default 0
    /// because the 36pt fixed header height already supplies
    /// enough margin around the 13pt header label.
    static func wrapColumn(_ subview: UIView,
        verticalInset: CGFloat = 0) -> UIView {
        let container = UIView()
        subview.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(subview)
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
