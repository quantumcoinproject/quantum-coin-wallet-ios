//
// SessionLock.swift
//
// Port of the idle-lock logic in `HomeActivity.java`:
//   - `UNLOCK_TIMEOUT_MS = 300_000` (5 min).
//   - Foreground idle timer resets on any UI interaction.
//   - `applicationDidBecomeActive` compares against the last unlock
//     timestamp and locks + presents the unlock dialog if the budget
//     elapsed or the clock went backwards.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/view/activities/HomeActivity.java
//

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
        if !KeyStore.shared.isMetadataLoaded {
            // Metadata is cleared. Two cases:
            //  1. Cold launch / splash: HomeViewController is not the
            //     rootVC yet, so `presentUnlockGate` -> `findHomeViewController`
            //     returns nil and this is a safe no-op. The dedicated
            //     cold-launch gate inside HomeViewController.routeInitialScreen
            //     remains the path that prompts here.
            //  2. Past-splash relock: a previous `lockAndPresent`
            //     ran (idle timer or >5min background resume),
            //     cleared metadata, but its `present(...)` was
            //     dropped by UIKit (e.g. raced a stale modal's
            //     dismiss). Without this re-attempt the user sees
            //     a blank shell with no unlock dialog until the
            //     next idle-timer cycle fires after they happen to
            //     tap. Re-dispatching `presentUnlockGate` here gets
            //     them prompted on the very next foreground.
            //
            // `presentUnlockGate` already short-circuits if the
            // dialog is mid-flight, so the cold-launch race is also
            // safe - at worst we no-op a second time.
            if KeyStore.shared.maxWalletIndex() >= 0 {
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
        KeyStore.shared.clearMetadata()
        // No wallet configured yet? Just drop the cached snapshot -
        // there's nothing for the user to unlock. Onboarding will set
        // a password when they create or import their first wallet,
        // and the cold-launch gate (`HomeViewController.routeInitialScreen`)
        // already gates that flow on `maxWalletIndex() >= 0`. Skipping
        // the dialog here fixes the bug where a long-foregrounded
        // brand-new install (no wallet ever created) would prompt for
        // an unlock password it doesn't have.
        guard KeyStore.shared.maxWalletIndex() >= 0 else { return }
        guard !KeyStore.shared.isMetadataLoaded else { return }
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
    /// `routeInitialScreen()` uses - so the wrong-password / wait /
    /// `showMain()` UX matches the rest of the app exactly.
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
    /// unlocked the vault, so the relock dialog isn't relevant).
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
        // Hook a pass-through tap recognizer on the key window so every
        // user interaction resets the idle timer. `cancelsTouchesInView`
        // = false keeps it transparent to downstream hit-testing.
        DispatchQueue.main.async {
            guard let scene = UIApplication.shared.connectedScenes
                    .compactMap({ $0 as? UIWindowScene }).first,
                  let window = scene.keyWindow ?? scene.windows.first else { return }
            let hook = UITapGestureRecognizer(target: self,
                                              action: #selector(self.anyInteraction))
            hook.cancelsTouchesInView = false
            hook.delegate = PassThroughGestureDelegate.shared
            window.addGestureRecognizer(hook)
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
