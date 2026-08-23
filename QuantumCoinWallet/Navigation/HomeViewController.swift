// HomeViewController.swift
// Single-activity / fragment-container port of `HomeActivity`. Owns
// the top banner, network chip, center wallet strip, fragment
// container, offline overlay, and bottom nav. Exposes
// `beginTransaction` / `beginTransactionNow` helpers that exactly
// mirror Android `FragmentTransaction.commit` / `commitNow`.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/activities/HomeActivity.java
// app/src/main/res/layout/home_activity.xml

import UIKit

public enum ScreenViewType: Int {
    case mainHome = 0 // show banner (wrap), network chip, center strip, bottom nav
    case onboarding = -1 // show banner (fixed), hide everything else
    case innerFragment = 1 // show banner (fixed), hide network + strip, show bottom nav
}

/// Coarse classification of the *primary* (non-Settings) tab the user
/// was last on. Settings does not appear here because it is the
/// destination, not a candidate back-target.
public enum PrimaryTab {
    case main // HomeMainViewController (wallet dashboard)
    case wallets // WalletsViewController
}

public final class HomeViewController: UIViewController {

    // MARK: - Chrome views

    private let topBannerView = TopBannerView()
    private let networkChipButton = UIButton(type: .system)
    private let centerStripView = CenterStripView()
    private let containerView = UIView()
    private let offlineOverlayView = OfflineOverlayView()
    private let drawerView = DrawerView()

    // MARK: - Child

    public private(set) var currentChild: UIViewController?

    /// Active layout state - drives banner height + container anchors.
    private var currentScreenViewType: ScreenViewType = .mainHome

    /// Most-recent primary tab the user landed on. Updated whenever
    /// `showMain` / `showWallets` runs, or the bottom nav routes
    /// directly to Wallets.
    private var lastSelectedTab: PrimaryTab = .main

    /// Snapshot of `lastSelectedTab` taken the moment the user enters
    /// Settings. `popFromSettings` reads this to decide whether back
    /// returns to the dashboard or the Wallets list. Defaults to
    /// `.main` so the first-ever tap on Settings (with no prior tab
    /// selection captured) still routes somewhere sensible.
    private var lastTabBeforeSettings: PrimaryTab = .main

    /// Container's top anchor is swapped per `ScreenViewType` so hidden
    /// chrome (network chip + center strip) does not reserve space on
    /// onboarding/inner-fragment screens. Mirrors Android's
    /// `screenViewType` which both `setVisibility(GONE)` and re-runs
    /// `setLayoutParams`.
    private var containerTopConstraint: NSLayoutConstraint?
    private var containerBottomConstraint: NSLayoutConstraint?

    /// Periodic balance poller. Mirrors Android `HomeActivity
    /// .notificationThread`'s `Thread.sleep` loop, but driven off
    /// `RunLoop.main` instead of a dedicated background thread.
    /// Balance only -- the token list is event-driven (load / wallet
    /// change / network change).
    ///
    /// Each tick samples a fresh interval from a uniform range so the
    /// public RPC sees a more even distribution of requests and no
    /// individual device falls into a predictable polling rhythm: the
    /// foreground app reschedules within [7s, 15s] and the
    /// backgrounded app reschedules within [60s, 120s]. iOS will
    /// eventually suspend the process while it's in the background,
    /// but as long as the process keeps running (e.g. while the user
    /// is in the app switcher) the slower cadence keeps it from
    /// hammering the scan API.
    private var balanceTimer: Timer?
    /// Slower than the Android doc's [7s, 15s] band: the public scan
    /// API rate-limits aggressively and balance + token list share the
    /// same host, so a tighter iOS cadence was tripping 429 in normal use.
    private static let foregroundIntervalRange: ClosedRange<TimeInterval> = 30...60
    private static let backgroundIntervalRange: ClosedRange<TimeInterval> = 90...180

    /// Re-entrancy guard for automatic balance refreshes so a slow
    /// poll can't stack repeated requests on top of each other.
    /// Manual taps bypass the guard unless the scan API is in backoff.
    private var balanceLoading = false
    /// Bumped whenever a newer balance fetch supersedes an in-flight
    /// one (e.g. returning home after Send). Stale tasks skip UI
    /// updates in `defer` so they cannot hide a newer request's spinner.
    private var balanceFetchGeneration = 0

    /// One-shot timer that re-enables refresh when a 429 backoff ends.
    private var rateLimitReenableTimer: Timer?

    /// Avoid stacking identical rate-limit dialogs on every refresh tap.
    private var rateLimitDialogShown = false

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground

        [topBannerView, centerStripView,
            containerView, offlineOverlayView, drawerView].forEach {
            $0.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview($0)
        }

        // The network chip lives in the banner's top-right corner now
        // (mirroring Android `imageButton_home_network`). Style and
        // install it before the rest of the layout depends on its
        // intrinsic size.
        styleNetworkChipButton()
        networkChipButton.addTarget(self, action: #selector(openNetworkPicker), for: .touchUpInside)
        topBannerView.setNetworkChipView(networkChipButton)

        topBannerView.onBurgerTap = { [weak self] in self?.drawerView.open() }
        drawerView.onSelect = { [weak self] item in self?.handleDrawerSelect(item) }
        centerStripView.onSend = { [weak self] in self?.presentSendFlow() }
        centerStripView.onReceive = { [weak self] in self?.presentReceive() }
        centerStripView.onTransactions = { [weak self] in self?.presentTransactions() }
        centerStripView.onRefresh = { [weak self] in self?.refreshBalance(manual: true) }
        centerStripView.onExploreAddress = { [weak self] in
            self?.openBlockExplorerForCurrentAddress()
        }

        // Static anchors. The container's top/bottom are stored separately
        // so they can be swapped per ScreenViewType in `apply(_:)`.
        NSLayoutConstraint.activate([
                // Pin the banner *frame* to the very top of the window so
                // the gradient bleeds into the status-bar / Dynamic-Island
                // strip on notched devices (filling what was previously a
                // `colorBackground` gutter alongside the camera cut-out).
                // The banner's inner content (logo, title, network chip)
                // is anchored to `safeAreaLayoutGuide.topAnchor` *inside*
                // `TopBannerView`, so nothing is actually clipped by the
                // notch. The matching height bump in
                // `viewDidLayoutSubviews` keeps the banner's *bottom* edge
                // invariant in screen space, so the centre wallet strip
                // and inner-fragment containers do not shift.
                topBannerView.topAnchor.constraint(equalTo: view.topAnchor),
                topBannerView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                topBannerView.trailingAnchor.constraint(equalTo: view.trailingAnchor),

                // Network chip is now docked inside `topBannerView` (see
                // setNetworkChipView), so the strip can sit immediately
                // below the banner with only a tiny 4pt gap, matching
                // Android `home_activity.xml` where `linearLayout_home_top`
                // butts directly against the banner.
                centerStripView.topAnchor.constraint(equalTo: topBannerView.bottomAnchor, constant: 4),
                centerStripView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                centerStripView.trailingAnchor.constraint(equalTo: view.trailingAnchor),

                containerView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                containerView.trailingAnchor.constraint(equalTo: view.trailingAnchor),

                offlineOverlayView.topAnchor.constraint(equalTo: containerView.topAnchor),
                offlineOverlayView.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
                offlineOverlayView.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),
                offlineOverlayView.bottomAnchor.constraint(equalTo: containerView.bottomAnchor),

                drawerView.topAnchor.constraint(equalTo: view.topAnchor),
                drawerView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
                drawerView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                drawerView.trailingAnchor.constraint(equalTo: view.trailingAnchor)
            ])

        // Seed the swappable container anchors with `.mainHome` defaults.
        // `apply(_:)` will rewire them as soon as a child VC is attached.
        containerTopConstraint = containerView.topAnchor.constraint(
            equalTo: centerStripView.bottomAnchor, constant: 4)
        containerBottomConstraint = containerView.bottomAnchor.constraint(
            equalTo: view.safeAreaLayoutGuide.bottomAnchor)
        containerTopConstraint?.isActive = true
        containerBottomConstraint?.isActive = true

        refreshNetworkChip()
        // Re-render the chip whenever BlockchainNetworkManager swaps
        // its active network (post-unlock applyDecryptedConfig, picker
        // setActive, lockWallet resetToBundled). Avoids stale text on
        // the main screen after the user switches networks via the
        // picker and pops back, and ensures the chip flips to the
        // user's saved selection the instant the strongbox unlock
        // completes.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleNetworkConfigDidChange),
            name: .networkConfigDidChange,
            object: nil)

        // Apply uniform alpha-dim press feedback to the network chip
        // pill plus any other UIControl in the chrome surface. The
        // CenterStrip / BottomNav / OfflineOverlay subviews wire their
        // own children inside their inits, so this recursive sweep
        // mostly catches the network chip - but it's idempotent so
        // calling it here is safe.
        view.installPressFeedbackRecursive()

        routeInitialScreen()

        // Foreground / background lifecycle observers swap the
        // balance-poll cadence between 10s (foreground) and 300s
        // (background) so a backgrounded app doesn't keep pinging
        // the scan API at full speed while iOS hasn't yet
        // suspended us. `willEnterForeground` also kicks an
        // immediate refresh so the user sees fresh data without
        // waiting up to 10s after a re-entry.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleAppDidEnterBackground),
            name: UIApplication.didEnterBackgroundNotification,
            object: nil)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleAppWillEnterForeground),
            name: UIApplication.willEnterForegroundNotification,
            object: nil)
        // Pull-to-refresh on `HomeMainViewController.table` posts this
        // so the host controller re-issues the balance fetch in
        // lockstep with the token table reload. Kept decoupled via
        // NotificationCenter exactly like `.networkConfigDidChange`.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleWalletHomeRefreshRequested),
            name: .walletHomeRefreshRequested,
            object: nil)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleScanApiRateLimitNotifyUser),
            name: .scanApiRateLimitNotifyUser,
            object: nil)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleScanApiThrottleDidChange),
            name: .scanApiThrottleDidChange,
            object: nil)

        updateRefreshAvailability()
        scheduleNextBalanceTick()
    }

    deinit {
        balanceTimer?.invalidate()
        rateLimitReenableTimer?.invalidate()
        NotificationCenter.default.removeObserver(self)
    }

    /// Schedule the next auto-refresh tick with a uniformly-random
    /// interval sampled from the foreground or background range
    /// depending on the live `applicationState`. Always invalidates
    /// the previous timer first so a foreground/background flip
    /// never leaves two timers ticking. Scheduled on `.common` mode
    /// so active scroll/tracking gestures do not pause the tick.
    /// When the tick fires it kicks `refreshBalance(manual: false)`
    /// and then re-schedules itself with a freshly-sampled interval -
    /// the recursive sampling is what gives the foreground app the
    /// [7s, 15s] uniform-random cadence (and [60s, 120s] backgrounded).
    private func scheduleNextBalanceTick() {
        balanceTimer?.invalidate()
        let range: ClosedRange<TimeInterval>
        if ScanApiRateLimiter.shared.isThrottled() {
            range = Self.backgroundIntervalRange
        } else {
            range = (UIApplication.shared.applicationState == .active)
                ? Self.foregroundIntervalRange
                : Self.backgroundIntervalRange
        }
        let interval = TimeInterval.random(in: range)
        let t = Timer.scheduledTimer(
            withTimeInterval: interval, repeats: false) { [weak self] _ in
            guard let self = self else { return }
            self.refreshBalance(manual: false)
            self.scheduleNextBalanceTick()
        }
        RunLoop.main.add(t, forMode: .common)
        balanceTimer = t
    }

    @objc private func handleAppDidEnterBackground() {
        // Re-sample so the next interval lands in the slower
        // backgrounded range. The in-flight tick is left alone -
        // the next one will already use the new range.
        scheduleNextBalanceTick()
    }

    @objc private func handleAppWillEnterForeground() {
        // Re-sample into the faster foreground range and kick an
        // immediate one-off refresh so the user does not stare at a
        // potentially-stale balance for the first sampled interval
        // after returning to the app — unless the scan API is in a
        // global 429 backoff window.
        scheduleNextBalanceTick()
        if !ScanApiRateLimiter.shared.isThrottled() {
            refreshBalance(manual: false)
        }
    }

    /// Pull-to-refresh dispatch from `HomeMainViewController`. Treat
    /// as a manual refresh so the user sees an error dialog if the
    /// balance fetch fails (the existing balance label is preserved).
    @objc private func handleWalletHomeRefreshRequested() {
        refreshBalance(manual: true)
    }

    @objc private func handleScanApiRateLimitNotifyUser() {
        presentRateLimitWaitDialogIfNeeded()
    }

    @objc private func handleScanApiThrottleDidChange() {
        updateRefreshAvailability()
    }

    @objc private func handleNetworkConfigDidChange() {
        refreshNetworkChip()
        // Center-strip main-coin balance must reload against the new
        // network's `accountBalance` endpoint. Token rows + tx lists
        // refresh themselves via their own observers.
        refreshBalance(manual: false)
    }

    public override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        // Banner height = 30% of screen width on first launch
        // (`HomeActivity.screenViewType(-1)`); other states use the
        // wrap-content baseline (logo 50pt + title + padding ~ 80pt).
        let target: CGFloat
        switch currentScreenViewType {
            case .onboarding:
            target = view.bounds.width * 0.30
            case .mainHome, .innerFragment:
            // 96pt (was 80) so the centered "Quantum Coin (Q)" title has
            // breathing room below it on the main wallet screen,
            // matching Android `home_activity.xml` `imageView_home_logo`
            // + `textView_home_tile` block which lays out at ~96dp tall.
            target = 96
        }
        // `safeAreaInsets.top` is 0 in landscape / iPad split-view, ~20pt
        // on a status-bar-only phone (iPhone SE), and ~47-59pt on notch /
        // Dynamic-Island devices. Adding it here keeps the banner's
        // bottom-edge fixed (so the centre strip / inner-fragment
        // container does not shift) while letting the gradient fill the
        // strip beside the camera cut-out.
        let extra = max(0, view.safeAreaInsets.top)
        topBannerView.setHeight(target + extra)
    }

    public override func viewSafeAreaInsetsDidChange() {
        super.viewSafeAreaInsetsDidChange()
        // Rotation / status-bar visibility / split-view changes alter
        // the inset; nudge a fresh layout pass so `viewDidLayoutSubviews`
        // re-runs the banner-height math.
        view.setNeedsLayout()
    }

    public override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        // Safety net for the cold-launch present-from-viewDidLoad
        // race: `routeInitialScreen` runs from viewDidLoad and, on
        // a locked + has-wallets cold launch, immediately tries to
        // `present(...)` the unlock gate. UIKit can silently drop
        // that present while the rootViewController swap is still
        // in flight, leaving the user staring at an empty chrome
        // shell with no prompt.
        // viewDidAppear is the safest moment to present a modal -
        // the view is unambiguously on screen and UIKit is settled.
        // Re-attempt here if we're still in the locked/no-modal
        // state. The guards make this idempotent across repeated
        // viewDidAppear fires (e.g. after dismissing a child sheet
        // or returning from background).
        if !Strongbox.shared.isSnapshotLoaded
        && hasExistingWallets()
        && presentedViewController == nil {
            presentUnlockGate()
        }
    }

    // MARK: - Initial routing (mirrors HomeActivity branching)

    private func routeInitialScreen() {
        if !Strongbox.shared.isSnapshotLoaded && hasExistingWallets() {
            presentUnlockGate()
            return
        }
        if hasExistingWallets() {
            showMain()
        } else {
            beginTransactionNow(HomeStartViewController())
            apply(.onboarding)
        }
    }

    /// True if at least one strongbox slot file exists on disk.
    /// Source of truth for the cold-launch routing because the
    /// in-memory snapshot is empty before the user has unlocked,
    /// and a `Strongbox.shared.maxWalletIndex` consult would
    /// otherwise return `-1` and route a returning user into the
    /// onboarding flow.
    private func hasExistingWallets() -> Bool {
        if case .strongboxPresent = UnlockCoordinatorV2.bootState() {
            return true
        }
        return false
    }

    /// Public re-entry from `SessionLock` after the 5-min idle relock
    /// fires. The metadata snapshot has already been cleared, so the
    /// in-memory address map is empty and `centerStripView` would
    /// otherwise be stuck displaying the now-stale address. This
    /// helper:
    /// - Tears down any modal that might have been on top when the
    /// user backgrounded the app (a leftover wait dialog, picker,
    /// confirmation sheet, ...). UIKit silently rejects a
    /// `present(...)` from a presenter that already has its own
    /// presented chain, so without the dismiss-first pass the
    /// unlock dialog never appears.
    /// - Blanks the strip's `currentAddress` so the user sees a
    /// cleanly locked state instead of stale data.
    /// - Routes to the same cold-launch unlock gate the very first
    /// `routeInitialScreen` uses, so success / wrong-password
    /// UX matches the rest of the app.
    public func relockAndPresentUnlock() {
        // Blank the strip first so the user never sees the stale
        // address through any brief gap between the dismiss
        // completing and the unlock gate fading in.
        centerStripView.currentAddress = ""
        if presentedViewController != nil {
            // `dismiss(animated:false)` still hands UIKit an async
            // tear-down; calling `present(...)` on the same runloop
            // tick races the in-flight dismissal and UIKit silently
            // drops the new present (the user-visible bug: metadata
            // is cleared, strip is blank, but no unlock dialog
            // surfaces until a later idle-timer cycle re-fires the
            // relock).
            // Wait for the dismiss completion before presenting so
            // the presentation chain is empty by the time we try to
            // surface the gate.
            dismiss(animated: false) { [weak self] in
                self?.presentUnlockGate()
            }
        } else {
            presentUnlockGate()
        }
    }

    private func presentUnlockGate() {
        let dlg = UnlockDialogViewController()
        // Cold-launch gate: the user has at least one wallet, so they
        // MUST unlock before the wallets list / main strip render.
        // Mandatory mode hides Close, blocks swipe-down, and rejects
        // any non-unlock dismiss attempt.
        dlg.isMandatory = true
        dlg.onUnlock = { [weak self, weak dlg] pw in
            guard let dlg = dlg else { return }
            if pw.isEmpty {
                // Surface a specific empty-password message via the
                // shared orange "exclamation triangle + OK" alert.
                // The unlock dialog stays alive underneath so any
                // typed value (none on the cold-launch gate, but the
                // pattern is uniform with every other unlock site)
                // is preserved.
                dlg.showOrangeError(Localization.shared.getEmptyPasswordByErrors())
                return
            }
            // The unlock helper runs scrypt key-derivation, which
            // can take a few seconds on first launch; surface the
            // standard "Please wait while..." dialog over the unlock
            // sheet so the UI is not visibly frozen. Mirrors the
            // pattern used by `BackupOptionsViewController.runBackupFlow`.
            let wait = WaitDialogViewController(
                message: Localization.shared.getWaitUnlockByLangValues())
            dlg.present(wait, animated: true)
            Task.detached(priority: .userInitiated) { [weak self, weak dlg, weak wait] in
                var failure: Error? = nil
                do {
                    // `unlockWithPasswordAndApplySession` runs the
                    // limiter pre-check, scrypt+AEAD unlock, and
                    // dispatches `SessionLock.markUnlockedNow` +
                    // `BlockchainNetworkManager.applyDecryptedConfig`
                    // internally on success - we don't repeat them
                    // here.
                    try UnlockCoordinatorV2.unlockWithPasswordAndApplySession(pw)
                } catch {
                    failure = error
                }
                let err = failure
                await MainActor.run {
                    wait?.dismiss(animated: true) {
                        if err == nil {
                            // First successful unlock is the moment
                            // Android starts its notification thread;
                            // mirror by asking for notification
                            // permission here. Calls are idempotent -
                            // iOS short-circuits the prompt once the
                            // user has answered.
                            BalanceChangeNotifier.shared
                                .requestAuthorizationIfNeeded()
                            dlg?.dismiss(animated: true) {
                                self?.showMain()
                            }
                        } else {
                            // Wrong-password branch: orange alert
                            // layered on top of the unlock dialog.
                            // `clearField` is intentionally NOT
                            // called so the typed password is
                            // preserved for typo-fix retry.
                            // Distinguish brute-force
                            // lockout from a regular wrong-password.
                            // Showing the generic "wrong password"
                            // string during lockout would confuse the
                            // user ("but I typed it correctly!");
                            // showing the "wait N seconds" message
                            // tells them the gate is throttling them
                            // by design. See UnlockAttemptLimiter.
                            if let uc = err as? UnlockCoordinatorV2Error,
                            case let .tooManyAttempts(seconds) = uc {
                                dlg?.showOrangeError(
                                    UnlockAttemptLimiter.userFacingLockoutMessage(
                                        remainingSeconds: seconds))
                            } else {
                                dlg?.showOrangeError(
                                    Localization.shared.getWalletPasswordMismatchByErrors())
                            }
                        }
                    }
                }
            }
        }
        // Cold-launch routing runs from `viewDidLoad`, before UIKit
        // has settled the rootViewController-swap transition kicked
        // off in AppDelegate's bootstrap completion. A synchronous
        // `present(...)` from that window is silently dropped, which
        // leaves the user staring at an empty chrome shell with no
        // unlock prompt. Hopping one runloop tick lets UIKit finish
        // the swap before we try to present.
        // The relock path also flows through this method (via
        // `relockAndPresentUnlock` -> `dismiss` completion -> here),
        // and the additional async hop is imperceptible there.
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            // Guard against double-present from the viewDidAppear
            // safety-net retry or a relock dispatch racing this
            // deferred present. UnlockDialog is the only mandatory
            // full-screen modal at this stage, so identity-checking
            // by type is sufficient.
            if self.presentedViewController is UnlockDialogViewController { return }
            self.present(dlg, animated: true)
        }
    }

    // MARK: - Public navigation helpers

    /// Async swap (mirrors `FragmentTransaction.commit`).
    public func beginTransaction(_ vc: UIViewController) {
        DispatchQueue.main.async { [weak self] in self?.replaceChild(vc) }
    }

    /// Synchronous swap (mirrors `commitNow`).
    public func beginTransactionNow(_ vc: UIViewController) {
        replaceChild(vc)
    }

    private func replaceChild(_ vc: UIViewController) {
        if let cur = currentChild {
            cur.willMove(toParent: nil)
            cur.view.removeFromSuperview()
            cur.removeFromParent()
        }
        offlineOverlayView.isHidden = true
        addChild(vc)
        vc.view.translatesAutoresizingMaskIntoConstraints = false
        containerView.addSubview(vc.view)
        NSLayoutConstraint.activate([
                vc.view.topAnchor.constraint(equalTo: containerView.topAnchor),
                vc.view.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
                vc.view.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),
                vc.view.bottomAnchor.constraint(equalTo: containerView.bottomAnchor)
            ])
        vc.didMove(toParent: self)
        currentChild = vc
        if let screenViewProvider = vc as? HomeScreenViewTypeProviding {
            apply(screenViewProvider.screenViewType)
        }
    }

    // MARK: - Screen view type

    public func apply(_ type: ScreenViewType) {
        currentScreenViewType = type

        // Visibility - keep the existing flips so chrome views aren't
        // visually shown when hidden.
        switch type {
            case .mainHome:
            topBannerView.isHidden = false
            networkChipButton.isHidden = false
            centerStripView.isHidden = false
            centerStripView.refreshBalanceLoadingAppearanceIfNeeded()
            topBannerView.setBurgerHidden(false)
            case .onboarding:
            topBannerView.isHidden = false
            networkChipButton.isHidden = true
            centerStripView.isHidden = true
            topBannerView.setBurgerHidden(true)
            drawerView.close()
            case .innerFragment:
            topBannerView.isHidden = false
            networkChipButton.isHidden = true
            centerStripView.isHidden = true
            topBannerView.setBurgerHidden(false)
        }

        // Layout collapse - rebind container's top/bottom so hidden views
        // do not reserve any vertical space. Mirrors Android's
        // `screenViewType` which rewires LayoutParams on every state.
        containerTopConstraint?.isActive = false
        containerBottomConstraint?.isActive = false

        let topAnchorView: NSLayoutYAxisAnchor
        let topConstant: CGFloat
        switch type {
            case .mainHome:
            topAnchorView = centerStripView.bottomAnchor
            topConstant = 4
            case .innerFragment, .onboarding:
            topAnchorView = topBannerView.bottomAnchor
            topConstant = 8
        }

        // No footer any more: the content container always extends to
        // the bottom safe area (the freed space goes to the body).
        let bottomAnchorView = view.safeAreaLayoutGuide.bottomAnchor

        containerTopConstraint = containerView.topAnchor.constraint(
            equalTo: topAnchorView, constant: topConstant)
        containerBottomConstraint = containerView.bottomAnchor.constraint(
            equalTo: bottomAnchorView)
        containerTopConstraint?.isActive = true
        containerBottomConstraint?.isActive = true

        // Force a layout pass so the banner height + container
        // anchors update before the next render frame.
        view.setNeedsLayout()
        view.layoutIfNeeded()
    }

    // MARK: - Offline overlay

    /// Matches `HomeActivity.shouldShowHomeOfflineOverlay`: only surface
    /// the overlay for the main screen.
    public func showOfflineOverlay(isNetworkError: Bool) {
        guard currentChild == nil || currentChild is HomeMainViewController else { return }
        offlineOverlayView.configure(isNetworkError: isNetworkError)
        offlineOverlayView.isHidden = false
    }

    // MARK: - Actions

    /// Top-right network chip taps now open a modal radio dialog
    /// instead of pushing the read-only Networks table. The dialog's OK
    /// handler calls `BlockchainNetworkManager.setActive(index:)` which
    /// posts `.networkConfigDidChange`; the existing observer in
    /// `viewDidLoad` already refreshes the chip label on that event.
    /// The Settings -> Networks entry point still pushes the table.
    @objc private func openNetworkPicker() {
        present(BlockchainNetworkSelectDialogViewController(), animated: true)
    }

    /// Burger menu rows (replaces the bottom navigation).
    private func handleDrawerSelect(_ item: DrawerView.Item) {
        switch item {
            case .wallets:
            lastSelectedTab = .wallets
            beginTransactionNow(WalletsViewController()); apply(.innerFragment)
            case .settings:
            lastTabBeforeSettings = lastSelectedTab
            beginTransactionNow(SettingsViewController()); apply(.innerFragment)
        }
    }

    /// Called by `SettingsViewController`'s back arrow. Returns the
    /// user to whichever primary tab they were on the instant they
    /// entered Settings (`.main` -> `showMain`, `.wallets` ->
    /// `showWallets`). Mirrors how `handleBottomNavTap` would itself
    /// route, just driven by the captured `lastTabBeforeSettings`.
    public func popFromSettings() {
        switch lastTabBeforeSettings {
            case .wallets:
            showWallets()
            case .main:
            showMain()
        }
    }

    /// Resolve the block explorer base URL with an Android-equivalent
    /// fallback chain: prefer the global `Constants.BLOCK_EXPLORER_URL`
    /// (set when a network is activated), else the active network's
    /// `blockExplorerUrl`, else empty (caller surfaces an error).
    private func resolveBlockExplorerBase() -> String {
        let primary = Constants.BLOCK_EXPLORER_URL
        if !primary.isEmpty { return primary }
        return BlockchainNetworkManager.shared.active?.blockExplorerUrl ?? ""
    }

    private func openBlockExplorer() {
        let base = resolveBlockExplorerBase()
        guard !base.isEmpty, let url = URL(string: base) else {
            showNoActiveNetworkDialog()
            return
        }
        UIApplication.shared.open(url)
    }

    /// Open the explorer's account-details page for the strip's
    /// currently-displayed address, mirroring Android
    /// `imageButton_home_open_explorer_link` (`open_explorer_link`).
    private func openBlockExplorerForCurrentAddress() {
        let base = resolveBlockExplorerBase()
        let address = centerStripView.currentAddress
        guard !base.isEmpty else {
            showNoActiveNetworkDialog()
            return
        }
        // Build via the validated wrapper so an
        // attacker-controlled address (e.g. from a token contract
        // returned by a hostile scan-API response) cannot smuggle
        // path/query/fragment metacharacters into the URL that gets
        // handed to UIApplication.shared.open. Returns nil and the
        // tap silently no-ops on validation failure.
        guard let url = UrlBuilder.blockExplorerAccountUrl(
            base: base, address: address) else { return }
        UIApplication.shared.open(url)
    }

    private func showNoActiveNetworkDialog() {
        let dlg = ConfirmDialogViewController(
            title: "",
            message: Localization.shared.getNoActiveNetworkByLangValues(),
            confirmText: Localization.shared.getOkByLangValues(),
            hideCancel: true)
        present(dlg, animated: true)
    }

    private func presentSendFlow() {
        beginTransactionNow(SendViewController())
        apply(.innerFragment)
    }
    private func presentReceive() {
        beginTransactionNow(ReceiveViewController())
        apply(.innerFragment)
    }
    private func presentTransactions() {
        beginTransactionNow(AccountTransactionsViewController())
        apply(.innerFragment)
    }

    /// Re-fetch the main coin balance.
    /// `manual = true` is reserved for explicit user action (the
    /// center-strip refresh button). On failure we surface a modal
    /// error dialog with OK and leave the previously-displayed balance
    /// value in place so the user keeps context.
    /// `manual = false` is used by the initial main-screen load,
    /// wallet/network-change observers, and the 5s periodic poll.
    /// Errors here are intentionally silent: any failure (4xx, 5xx,
    /// 429 rate-limit, decode mismatch, offline, ...) leaves the
    /// previous balance and token list untouched so a transient blip
    /// doesn't blank out the dashboard while a typing user wonders if
    /// their wallet is empty. Only the spinner stops.
    /// - Parameter force: When `true`, starts a new fetch even if an
    ///   automatic refresh is already in flight (used after Send so
    ///   the address-strip spinner is visible and the post-tx balance
    ///   is reloaded). Supersedes the prior task via
    ///   `balanceFetchGeneration`.
    private func refreshBalance(manual: Bool, force: Bool = false) {
        if !manual && !force && balanceLoading {
            // A poll may have started while the strip was hidden
            // (Send / Receive). Still show the spinner now that the
            // strip is visible again.
            centerStripView.setBalance(loading: true)
            return
        }
        let address = centerStripView.currentAddress
        guard !address.isEmpty else { return }

        balanceFetchGeneration += 1
        let generation = balanceFetchGeneration
        let fetchAddress = address
        balanceLoading = true
        centerStripView.setBalance(loading: true)
        Task { @MainActor [weak self] in
            guard let self = self else { return }
            guard generation == self.balanceFetchGeneration,
                  fetchAddress == self.centerStripView.currentAddress else { return }
            // Yield so the strip can lay out (especially right after
            // returning from Send) before a fast 429 short-circuit.
            await Task.yield()
            self.view.layoutIfNeeded()
            self.centerStripView.setBalance(loading: true)

            var keepSpinnerVisible = false
            defer {
                if generation == self.balanceFetchGeneration {
                    self.balanceLoading = false
                    if !keepSpinnerVisible {
                        self.centerStripView.setBalance(loading: false)
                    }
                }
            }

            if ScanApiRateLimiter.shared.isThrottled() {
                if manual {
                    self.presentRateLimitWaitDialogIfNeeded()
                }
                // After Send, keep the refresh spinner visible until the
                // backoff timer issues a real fetch (release the guard).
                if force {
                    keepSpinnerVisible = true
                }
                return
            }

            do {
                let resp = try await AccountsApi.accountBalance(address: fetchAddress)
                guard generation == self.balanceFetchGeneration,
                      fetchAddress == self.centerStripView.currentAddress else { return }
                let formatted = CoinUtils.formatWei(resp.result?.balance)
                self.centerStripView.setBalance(formatted)
                BalanceChangeNotifier.shared.observeBalance(
                    formatted, address: fetchAddress)
            } catch {
                guard generation == self.balanceFetchGeneration,
                      fetchAddress == self.centerStripView.currentAddress else { return }
                if case ApiError.http(let status, _) = error, status == 429 {
                    self.scheduleNextBalanceTick()
                    self.updateRefreshAvailability()
                }
                if manual {
                    if case ApiError.http(let status, let body) = error, status == 429 {
                        self.presentRateLimitWaitDialogIfNeeded(detail: body)
                    } else {
                        self.presentBalanceError(error)
                    }
                }
            }
        }
    }

    private func updateRefreshAvailability() {
        let throttled = ScanApiRateLimiter.shared.isThrottled()
        centerStripView.setRefreshEnabled(!throttled)
        rateLimitReenableTimer?.invalidate()
        rateLimitReenableTimer = nil
        if throttled {
            guard let seconds = ScanApiRateLimiter.shared.remainingSeconds() else { return }
            rateLimitReenableTimer = Timer.scheduledTimer(
                withTimeInterval: TimeInterval(seconds), repeats: false) { [weak self] _ in
                guard let self = self else { return }
                self.rateLimitDialogShown = false
                self.updateRefreshAvailability()
                self.centerStripView.setBalance(loading: false)
                self.balanceLoading = false
                if !ScanApiRateLimiter.shared.isThrottled() {
                    self.refreshBalance(manual: false)
                }
            }
            RunLoop.main.add(rateLimitReenableTimer!, forMode: .common)
        } else {
            rateLimitDialogShown = false
        }
    }

    /// Shown at most once per 429 backoff window.
    private func presentRateLimitWaitDialogIfNeeded(
        detail: String? = ApiError.scanApiRateLimitDetail
    ) {
        guard !rateLimitDialogShown else { return }
        rateLimitDialogShown = true
        presentRateLimitWaitDialog(detail: detail)
    }

    /// Shown when the user taps refresh while the scan API is in a
    /// global 429 backoff window (no network call is made).
    private func presentRateLimitWaitDialog(
        detail: String? = ApiError.scanApiRateLimitDetail
    ) {
        let L = Localization.shared
        let title = L.getErrorTitleByLangValues().isEmpty
        ? "Error"
        : L.getErrorTitleByLangValues()
        let body = "Unable to fetch balance: "
        + ApiError.rateLimitUserMessage(detail: detail)
        let dlg = MessageInformationDialogViewController.error(
            title: title, message: body)
        present(dlg, animated: true)
    }

    /// Dismiss-only error dialog for manual balance-refresh failures.
    private func presentBalanceError(_ error: Error) {
        let L = Localization.shared
        let title = L.getErrorTitleByLangValues().isEmpty
        ? "Error"
        : L.getErrorTitleByLangValues()
        let body: String
        if let api = error as? ApiError {
            body = "Unable to fetch balance: \(api.description)"
        } else {
            body = "Unable to fetch balance: \(error.localizedDescription)"
        }
        let dlg = MessageInformationDialogViewController.error(
            title: title, message: body)
        present(dlg, animated: true)
    }

    private func refreshNetworkChip() {
        let name = BlockchainNetworkManager.shared.active?.name ?? ""
        if #available(iOS 15.0, *), var cfg = networkChipButton.configuration {
            var attr = AttributedString(name)
            attr.font = Typography.body(12)
            attr.foregroundColor = UIColor(named: "colorCommon6") ?? .label
            cfg.attributedTitle = attr
            networkChipButton.configuration = cfg
        } else {
            networkChipButton.setTitle(name, for: .normal)
        }
    }

    /// Style the network-chip button to mirror Android
    /// `imageButton_home_network`: a small bordered pill with the
    /// network name + a `caret_down_outline` chevron on the trailing
    /// edge. Background is the `text_link_selector_bg`-style 1pt border
    /// + 4pt corner radius using `colorCommon6`.
    private func styleNetworkChipButton() {
        let chipColor = UIColor(named: "colorCommon6") ?? .label
        if #available(iOS 15.0, *) {
            var cfg = UIButton.Configuration.plain()
            cfg.image = UIImage(named: "caret_down_outline")?
            .withRenderingMode(.alwaysTemplate)
            cfg.imagePlacement = .trailing
            cfg.imagePadding = 4
            cfg.preferredSymbolConfigurationForImage = UIImage.SymbolConfiguration(
                pointSize: 10, weight: .regular)
            cfg.contentInsets = NSDirectionalEdgeInsets(
                top: 4, leading: 8, bottom: 4, trailing: 8)
            cfg.baseForegroundColor = chipColor
            networkChipButton.configuration = cfg
        } else {
            networkChipButton.setImage(
                UIImage(named: "caret_down_outline")?
                .withRenderingMode(.alwaysTemplate),
                for: .normal)
            networkChipButton.semanticContentAttribute = .forceRightToLeft
            networkChipButton.tintColor = chipColor
            networkChipButton.setTitleColor(chipColor, for: .normal)
        }
        networkChipButton.titleLabel?.font = Typography.body(12)
        networkChipButton.layer.borderWidth = 1
        networkChipButton.layer.borderColor = chipColor.withAlphaComponent(0.6).cgColor
        networkChipButton.layer.cornerRadius = 4
        networkChipButton.layer.masksToBounds = true
    }

    // MARK: - Show main

    /// Pop to the wallets list (used as the back-target for returning
    /// users who reached the onboarding "Create or restore" screen via
    /// the "+" add-wallet button on the wallets list).
    public func showWallets() {
        lastSelectedTab = .wallets
        beginTransactionNow(WalletsViewController())
        apply(.innerFragment)
    }

    /// Drop into the onboarding wizard at the create-or-restore step.
    /// Used by the "Create or Restore Quantum Wallet" link below the
    /// wallets table, mirroring Android `HomeActivity` lines 526-528
    /// (`screenViewType(1)` + `HomeWalletFragment`).
    public func showCreateOrRestore() {
        let vc = HomeWalletViewController()
        vc.step = .createOrRestore
        beginTransactionNow(vc)
        apply(.onboarding)
    }

    /// - Parameter refreshBalanceAfterNavigation: When `true`, always
    ///   kicks off a fresh balance fetch with the strip spinner (e.g.
    ///   after a successful Send). Defaults to `false` for ordinary
    ///   back-navigation where coalescing with an in-flight poll is
    ///   enough.
    public func showMain(refreshBalanceAfterNavigation: Bool = false) {
        lastSelectedTab = .main
        beginTransactionNow(HomeMainViewController())
        apply(.mainHome)
        // Refresh the network chip on every return-to-main hop so a
        // picker round-trip (BlockchainNetworkViewController) reflects
        // the new selection immediately, even if no notification
        // fired in between (e.g. selectionChanged + popViewController
        // both happened on the same run loop).
        refreshNetworkChip()
        // Populate the address strip with the active wallet so copy /
        // explore / refresh have something to operate on. Mirrors
        // Android `HomeActivity.onResume` populating the address text
        // from the current index in `PrefConnect`.
        let address = activeWalletAddress()
        let walletChanged = address != centerStripView.currentAddress
        centerStripView.currentAddress = address
        updateRefreshAvailability()
        if walletChanged {
            // Drop the previous wallet's balance immediately so the
            // strip never shows stale funds while the new fetch runs.
            centerStripView.setBalance("0")
        }
        let forceRefresh = refreshBalanceAfterNavigation || walletChanged
        if forceRefresh {
            centerStripView.setBalance(loading: true)
            view.layoutIfNeeded()
        }
        refreshBalance(manual: false, force: forceRefresh)
    }

    /// Returns the address tied to `WALLET_CURRENT_ADDRESS_INDEX_KEY`,
    /// or empty if no wallet has been persisted yet (or the strongbox is
    /// still locked - the in-memory map is cleared on lock so the
    /// address strip simply renders blank behind the dim until the
    /// user unlocks).
    private func activeWalletAddress() -> String {
        // The current-index pref is written via `writeInt` everywhere
        // (Wallets row tap, create / restore commit, RestoreFlow), so
        // read it via `readInt`. Reading via `readString` would silently
        // fall through to its default ("0") because `memo[key] as? String`
        // is `nil` for an `Int`-typed entry, leaving the user pinned to
        // wallet 0 even after they tap a different row.
        let idx = PrefConnect.shared.readInt(
            PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, default: 0)
        return Strongbox.shared.address(forIndex: idx) ?? ""
    }
}

/// Child VCs implement this to declare which shell state they want.
public protocol HomeScreenViewTypeProviding {
    var screenViewType: ScreenViewType { get }
}
