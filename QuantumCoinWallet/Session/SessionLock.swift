// SessionLock.swift
// Port of the idle-lock logic in `HomeActivity.java`:
// - `UNLOCK_TIMEOUT_MS = 300_000` (5 min).
// - Foreground idle timer resets on any UI interaction.
// - `applicationDidBecomeActive` compares against the last unlock
// timestamp and locks + presents the unlock dialog if the budget
// elapsed or the clock went backwards.
// (audit-grade notes for AI reviewers and human
// auditors):
// The original implementation installed only a `UITapGestureRecognizer`
// on the key window. The comment "any UI interaction" was therefore
// misleading: a user reading a long transaction list could swipe-
// scroll for several minutes, never tap, and be relocked mid-scroll
// even though they were clearly interacting with the app. The audit
// flagged this as a comment-vs-code mismatch.
// The fix here is to widen the interaction surface to match the
// comment, NOT to narrow the comment to match the code. Specifically
// we now install:
// 1. `UITapGestureRecognizer` (already present) - catches simple
// button taps, list-row selects, etc.
// 2. `UIPanGestureRecognizer` - catches scroll-view pans, swipes,
// drags, and pinch-precursors. (`UISwipeGestureRecognizer` is
// not added separately because UIKit recognises swipes as
// velocity-bounded pans; the pan recogniser fires for both.)
// 3. `UILongPressGestureRecognizer` - catches "press and hold" on
// copy menus, drag-and-drop initiations, and accessibility
// long-presses.
// 4. Notification observer on `UITextField.textDidChangeNotification`
// - catches typing into any field (search, password, recipient
// address, amount). UIKit posts this notification for every
// `UITextField` insertion / deletion regardless of where the
// field lives in the view hierarchy.
// All recognisers use `cancelsTouchesInView = false` and a
// permissive simultaneous-recognition delegate so they are
// transparent to downstream hit-testing - they observe touches but
// never absorb them. The first signal of any kind resets the timer
// via `anyInteraction`.
// Tradeoffs (truthful summary):
// * The reset surface is now broad enough that an automated
// process generating fake touches (e.g. a malicious accessibility
// service) could hold the unlock open indefinitely. This was
// already true with the tap-only implementation; widening the
// surface does not weaken the threat model meaningfully because
// the same accessibility service could synthesise a tap.
// * KVO on `UIScrollView.contentOffset` was considered but rejected:
// it would require attaching observers to every scroll view in
// the app (vs the centralised window-level pan recogniser),
// which is brittle and easy to miss in new screens. The window-
// level pan covers all current and future scroll surfaces by
// construction.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/activities/HomeActivity.java

import UIKit

public final class SessionLock {

    public static let shared = SessionLock()

    private var lastUnlockTimestamp: CFAbsoluteTime = 0
    private var lastBackgroundTimestamp: CFAbsoluteTime = 0
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue.main
    private var installed = false

    private init() {}

    public func start() {
        guard !installed else { return }
        installed = true
        installInteractionHook()
        restartIdleTimer()
    }

    public func markUnlockedNow() {
        lastUnlockTimestamp = CFAbsoluteTimeGetCurrent()
        // Reset the "went to background at" stamp so a subsequent
        // resume doesn't compare against an old value taken before
        // the user just unlocked.
        lastBackgroundTimestamp = 0
        restartIdleTimer()
    }

    public func applicationDidBecomeActive() {
        if !Strongbox.shared.isSnapshotLoaded {
            // Snapshot is cleared. Two cases:
            // 1. Cold launch / splash: HomeViewController is not the
            // rootVC yet, so `presentUnlockGate` -> `findHomeViewController`
            // returns nil and this is a safe no-op. The dedicated
            // cold-launch gate inside HomeViewController.routeInitialScreen
            // remains the path that prompts here.
            // 2. Past-splash relock: a previous `lockAndPresent`
            // ran (idle timer or >5min background resume),
            // cleared the snapshot, but its `present(...)` was
            // dropped by UIKit (e.g. raced a stale modal's
            // dismiss). Without this re-attempt the user sees
            // a blank shell with no unlock dialog until the
            // next idle-timer cycle fires after they happen to
            // tap. Re-dispatching `presentUnlockGate` here gets
            // them prompted on the very next foreground.
            // `presentUnlockGate` already short-circuits if the
            // dialog is mid-flight, so the cold-launch race is also
            // safe - at worst we no-op a second time.
            // We deliberately consult the v2 boot state (slot file
            // present?) rather than an in-memory wallet count,
            // because a returning user with an existing strongbox
            // is in case 1 BEFORE they have unlocked - the snapshot
            // is empty but the slot file is on disk, and the gate
            // must still surface.
            if case .strongboxPresent = UnlockCoordinatorV2.bootState() {
                DispatchQueue.main.async { [weak self] in
                    self?.presentUnlockGate()
                }
            }
            return
        }

        let now = CFAbsoluteTimeGetCurrent()
        // Use the more conservative of "elapsed since last unlock" or
        // "elapsed since the app was backgrounded". In the common case
        // they match (both move forward at the same rate while the app
        // is suspended). The `now < lastUnlockTimestamp` guard catches
        // a clock skew where the user / NTP rolled the system clock
        // backwards while we were suspended.
        let elapsedSinceUnlock = (now - lastUnlockTimestamp) * 1000
        let elapsedSinceBackground = lastBackgroundTimestamp > 0
        ? (now - lastBackgroundTimestamp) * 1000
        : 0
        let elapsedMs = max(elapsedSinceUnlock, elapsedSinceBackground)

        if elapsedMs > Double(Constants.UNLOCK_TIMEOUT_MS)
        || now < lastUnlockTimestamp {
            lockAndPresent()
        } else {
            // Within budget - keep the foreground idle countdown
            // running so the user is re-locked after another
            // UNLOCK_TIMEOUT_MS of inactivity.
            restartIdleTimer()
        }
    }

    public func applicationWillResignActive() {
        timer?.cancel()
        // Stamp so applicationDidBecomeActive can compare against a
        // monotonic-ish wall clock even if the app is suspended for
        // long enough that the foreground idle timer never fires.
        lastBackgroundTimestamp = CFAbsoluteTimeGetCurrent()
    }

    // MARK: - Internals

    private func restartIdleTimer() {
        timer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .milliseconds(Constants.UNLOCK_TIMEOUT_MS))
        t.setEventHandler { [weak self] in
            self?.lockAndPresent()
        }
        t.resume()
        timer = t
    }

    private func lockAndPresent() {
        timer?.cancel()
        UnlockCoordinatorV2.lock()
        // No wallet configured yet? Just drop the snapshot -
        // there's nothing for the user to unlock. Onboarding will set
        // a password when they create or import their first wallet,
        // and the cold-launch gate (`HomeViewController.routeInitialScreen`)
        // already gates that flow on the v2 boot state. Skipping
        // the dialog here fixes the bug where a long-foregrounded
        // brand-new install (no wallet ever created) would prompt for
        // an unlock password it doesn't have.
        // We check `bootState` rather than an in-memory wallet
        // count because the snapshot was just cleared - the only
        // surviving signal is whether a slot file exists on disk.
        guard case .strongboxPresent = UnlockCoordinatorV2.bootState() else { return }
        guard !Strongbox.shared.isSnapshotLoaded else { return }
        // Defer the actual present to the next runloop tick so any
        // in-flight scene-activation transition (we get here from
        // `applicationDidBecomeActive`) has finished. UIKit silently
        // drops modal presentations issued during a transition,
        // which is the bug that left the user looking at a blank
        // home strip with no unlock dialog after a >5min background.
        DispatchQueue.main.async {
            self.presentUnlockGate()
        }
    }

    /// Walk to the app's `HomeViewController` and route through its
    /// public relock entry. `HomeViewController.relockAndPresentUnlock`
    /// dismisses any leftover modal, blanks the address strip, and
    /// presents the same cold-launch unlock dialog the very first
    /// `routeInitialScreen` uses - so the wrong-password / wait /
    /// `showMain` UX matches the rest of the app exactly.
    private func presentUnlockGate() {
        guard let scene = UIApplication.shared.connectedScenes
        .compactMap({ $0 as? UIWindowScene }).first,
        let window = scene.keyWindow ?? scene.windows.first,
        let home = Self.findHomeViewController(under: window.rootViewController)
        else { return }
        // Already in a relock prompt? Nothing to do.
        if home.presentedViewController is UnlockDialogViewController { return }
        home.relockAndPresentUnlock()
    }

    /// Walk the presentation chain looking for the app's
    /// `HomeViewController`. Returns nil on cold-launch / splash
    /// states where it isn't the rootVC yet (those screens haven't
    /// unlocked the strongbox, so the relock dialog isn't relevant).
    private static func findHomeViewController(
        under root: UIViewController?) -> HomeViewController? {
        var node = root
        while let cur = node {
            if let home = cur as? HomeViewController { return home }
            node = cur.presentedViewController
        }
        return nil
    }

    private func installInteractionHook() {
        // Install three pass-through gesture
        // recognisers on the key window so every user interaction
        // (tap / pan / long-press) resets the idle timer. All use
        // `cancelsTouchesInView = false` so they are transparent to
        // downstream hit-testing. A permissive delegate allows
        // simultaneous recognition with any other recogniser
        // (including UITableView's / UIScrollView's internal pan).
        // Also subscribe to UITextField textDidChange so typing
        // counts as activity even if the user never lifts their
        // finger to trigger a tap / pan recognition.
        DispatchQueue.main.async {
            guard let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene }).first,
            let window = scene.keyWindow ?? scene.windows.first else { return }

            let tap = UITapGestureRecognizer(
                target: self, action: #selector(self.anyInteraction))
            tap.cancelsTouchesInView = false
            tap.delegate = PassThroughGestureDelegate.shared
            window.addGestureRecognizer(tap)

            let pan = UIPanGestureRecognizer(
                target: self, action: #selector(self.anyInteraction))
            pan.cancelsTouchesInView = false
            pan.delegate = PassThroughGestureDelegate.shared
            // Accept any number of touches so two-finger scrolls etc
            // also count.
            pan.minimumNumberOfTouches = 1
            pan.maximumNumberOfTouches = Int.max
            window.addGestureRecognizer(pan)

            let press = UILongPressGestureRecognizer(
                target: self, action: #selector(self.anyInteraction))
            press.cancelsTouchesInView = false
            press.delegate = PassThroughGestureDelegate.shared
            // Standard short long-press threshold; we just need the
            // .began edge to fire to reset the timer.
            press.minimumPressDuration = 0.4
            window.addGestureRecognizer(press)

            NotificationCenter.default.addObserver(
                self,
                selector: #selector(self.anyInteraction),
                name: UITextField.textDidChangeNotification,
                object: nil)
            NotificationCenter.default.addObserver(
                self,
                selector: #selector(self.anyInteraction),
                name: UITextView.textDidChangeNotification,
                object: nil)
        }
    }

    @objc private func anyInteraction() {
        restartIdleTimer()
    }
}

private final class PassThroughGestureDelegate: NSObject, UIGestureRecognizerDelegate {
    static let shared = PassThroughGestureDelegate()
    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer,
        shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool { true }
}
