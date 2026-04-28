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
        // If the metadata snapshot is already cleared, the cold-launch
        // gate (or whatever unlock path the user is in) is already
        // responsible for the prompt - we must not race-present a
        // second dialog here.
        guard KeyStore.shared.isMetadataLoaded else { return }

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
        presentUnlockDialog()
    }

    private func presentUnlockDialog() {
        guard let scene = UIApplication.shared.connectedScenes
                .compactMap({ $0 as? UIWindowScene }).first,
              let window = scene.keyWindow ?? scene.windows.first,
              let root = window.rootViewController else { return }
        if root.presentedViewController is UnlockDialogViewController { return }
        let dlg = UnlockDialogViewController()
        // Re-lock prompts must be non-dismissable. The user landed
        // here because their session expired; closing the dialog
        // without unlocking would leave them looking at a partially
        // populated screen with the in-memory address map cleared.
        dlg.isMandatory = true
        dlg.onUnlock = { [weak dlg] pw in
            guard let dlg = dlg else { return }
            if pw.isEmpty {
                // Empty-password message surfaced as the shared
                // orange OK alert layered on top of the re-lock
                // dialog. Field stays editable; the password field
                // is refocused once the alert is dismissed (handled
                // inside `showOrangeError`).
                dlg.showOrangeError(Localization.shared.getEmptyPasswordByErrors())
                return
            }
            // `KeyStore.unlock` runs scrypt key-derivation, which can
            // take a few seconds; surface the standard
            // "Please wait while..." dialog over the unlock sheet so
            // the UI is not visibly frozen during idle re-lock.
            // Mirrors the cold-launch path in
            // `HomeViewController.presentUnlockThenRoute`.
            let wait = WaitDialogViewController(
                message: Localization.shared.getWaitUnlockByLangValues())
            dlg.present(wait, animated: true)
            Task.detached(priority: .userInitiated) { [weak dlg, weak wait] in
                var failure: Error? = nil
                do {
                    // KeyStore.unlock(password:) calls markUnlockedNow()
                    // internally on success, so we don't repeat it here.
                    try KeyStore.shared.unlock(password: pw)
                } catch {
                    failure = error
                }
                let err = failure
                await MainActor.run {
                    wait?.dismiss(animated: true) {
                        if err == nil {
                            dlg?.dismiss(animated: true)
                        } else {
                            // Wrong-password branch: orange OK alert
                            // layered on top of the re-lock dialog.
                            // Typed password preserved (no
                            // `clearField()`).
                            dlg?.showOrangeError(
                                Localization.shared.getWalletPasswordMismatchByErrors())
                        }
                    }
                }
            }
        }
        let presenter = root.presentedViewController ?? root
        presenter.present(dlg, animated: true)
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
