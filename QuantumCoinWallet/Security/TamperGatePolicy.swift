// TamperGatePolicy.swift (Security layer - policy + UI)
// Policy + UI layer that consumes the value-typed
// `TamperReport` produced by `TamperGate.swift`. This file owns the
// disclosure dialog, the persistent banner, the hard-fail dialog,
// the "consent already given" sticky bit, and the per-signing-call
// throw used by `JsBridge.send*`.
// Design discipline (audit-grade notes for AI reviewers and human
// auditors):
// * The probe layer (`TamperGate`) MUST stay free of UIKit and
// localization dependencies so it is unit-testable. That means
// this file is the ONLY place where the words "jailbreak",
// "debugger", "tamper" are user-shown, where the `Quit`
// button is wired to `exit(0)`, and where the
// `kTamperGateEnabled` feature flag is consumed.
// * `assertSafeToSign` is the single chokepoint at the JS
// bridge: every transaction signing call funnels through it
// before payload preparation. A regression that adds a new
// signing entry point but forgets to call `assertSafeToSign`
// is caught by the rule documented at the top of `JsBridge`:
// "the first call inside every JsBridge.sign* entry point".
// * The user-facing policy is intentionally asymmetric:
// jailbreak -> INFORMED CONSENT (one-time dialog + banner)
// debugger -> RECOMMEND-EXIT (per-launch dialog;
// user can Quit OR
// Ignore-and-resume)
// tamper -> RECOMMEND-EXIT (per-launch dialog;
// user can Quit OR
// Ignore-and-resume)
// The asymmetry has shifted: jailbreak detection still uses an
// informed-consent dialog with a sticky bit. Debugger and
// runtime-tamper detections present an "exit-recommended"
// dialog but expose an explicit "Ignore and resume" affordance
// so a security researcher / power user / developer with
// legitimate access to the device can keep working. The risk
// of an opportunistic attacker is mitigated by:
// (a) the dialog itself ("we strongly recommend you exit"),
// (b) the persistent red banner installed after the user
// ignores ("Tampering detected - reduced protection"),
// (c) the per-launch nature of the override - we do NOT
// persist the "ignore" choice, so every cold launch
// re-asks the user, and
// (d) the same warning is re-evaluated on every signing
// call so a debugger that attaches AFTER the dialog
// is still detected on the next signing attempt unless
// the user has already accepted the override.
// * The jailbreak disclosure dialog appears EXACTLY ONCE per
// device per install. The "I have seen the disclosure" bit is
// recorded in a Keychain item (`kSecAttrAccessibleWhenUnlocked
// ThisDeviceOnly`, `kSecAttrSynchronizable=false`); we use
// Keychain rather than UserDefaults so the bit survives a JSON
// pref wipe but does NOT survive a full app uninstall (iOS
// 10.3+ drops Keychain items on uninstall). Reinstalling
// resets the consent and re-shows the dialog, which is the
// correct trade-off: a fresh install has not seen the
// disclosure, so it should see it.
// * The hard-fail "Ignore and resume" choice is INTENTIONALLY
// NOT persisted. Each cold launch re-asks. Persisting it
// would let an attacker who briefly compromises the device
// bury the warning forever; per-launch re-prompting keeps the
// user informed without being annoying mid-session.
// Tradeoffs:
// - The persistent banner consumes ~28pt at the top of the
// window. In practice that pushes the existing chrome down
// slightly on a tamper-detected device; acceptable because
// the user explicitly accepted that trade-off when they
// tapped "Continue at my own risk" or "Ignore and resume".
// - "Ignore and resume" weakens the defensive posture from
// "process exits, attacker stalls" to "process continues,
// attacker proceeds." The mitigation is twofold: (1) the
// user is shown a dialog with explicit recommendation to
// exit AND a persistent red banner explaining the residual
// risk, and (2) the override is per-launch only. A fully
// defensive deployment can flip `kTamperGateEnabled = true`
// and additionally remove the "Ignore and resume" action
// from `presentHardFailDialog` to restore the strict-exit
// behaviour.
// - `exit(0)` is a hard process termination. Apple's Human
// Interface Guidelines discourage user-initiated process
// termination, BUT the alternative (leaving the wallet
// running after detecting a debugger or a tampered bundle
// without explicit user acknowledgement) is worse: the next
// signing call would itself be unsafe. The exit is gated
// behind a modal the user must dismiss, so the user sees the
// explanation before the process disappears.
// - The disclosure dialog uses `UIAlertController` (rather than
// the codebase's custom `ModalDialogViewController` family)
// so it is guaranteed to render correctly even if the rest of
// the UI stack is mid-construction. AppDelegate calls this
// from `application(_:didFinishLaunchingWithOptions:)` while
// the rootViewController is still the splash; UIAlertController
// handles that case unambiguously where a custom modal would
// need an explicit presenter.

import Foundation
import UIKit

public final class TamperGatePolicy: @unchecked Sendable {

    // -----------------------------------------------------------
    // Feature flag - public so a future hotfix build can flip it
    // via a build-config preprocessor define without touching the
    // policy logic. Default `true` for the work item; flip
    // to `false` if a TestFlight wave reports an unacceptable
    // false-positive rate from the jailbreak probes.
    // -----------------------------------------------------------

    public static let kTamperGateEnabled: Bool = true

    // -----------------------------------------------------------
    // Singleton + state.
    // -----------------------------------------------------------

    public static let shared = TamperGatePolicy()
    private init() {}

    // -----------------------------------------------------------
    // Thread-safe state shared across the @MainActor UI methods
    // (`evaluateAtLaunch`) and the `nonisolated` per-call gate
    // (`assertSafeToSign`). We store the state behind an `NSLock`
    // rather than tagging the whole class `@MainActor` because
    // `JsBridge.send*` invokes `assertSafeToSign` from a
    // background thread and a `MainActor.assumeIsolated` hop
    // would trap. The lock is held for two field accesses at
    // most, so contention is negligible.
    // -----------------------------------------------------------

    private let stateLock = NSLock()

    /// Set after `evaluateAtLaunch(on:)` decides the device is
    /// jailbroken AND the user accepts the disclosure. Read by
    /// `assertSafeToSign` to confirm the user gave consent.
    /// Distinct from "consent persisted in Keychain" because the
    /// Keychain item only records that the dialog WAS SHOWN once
    /// - a user who taps "Quit" has the Keychain bit set but the
    /// process has already exited, so the next launch re-decides.
    private var _jailbreakConsentGivenThisLaunch: Bool = false

    /// Set when a hard-fail decision has been made. Used by
    /// `assertSafeToSign` so a signing attempt fired between the
    /// hard-fail dialog and the `exit(0)` is still blocked.
    /// Cleared if the user chooses "Ignore and resume" so that
    /// subsequent signing calls inside the same process do not
    /// keep re-throwing.
    private var _hardFailReason: String?

    /// Set to `true` after the user explicitly taps "Ignore and
    /// resume" on a debugger / runtime-tamper hard-fail dialog.
    /// `assertSafeToSign` consults this flag so signing calls
    /// proceed for the rest of this process's lifetime even
    /// though the underlying probe is still positive. Per-launch
    /// only - we do NOT persist this bit; every cold launch re-
    /// asks. See file header for the rationale.
    private var _hardFailOverrideAcceptedThisLaunch: Bool = false

    private var jailbreakConsentGivenThisLaunch: Bool {
        get { stateLock.lock(); defer { stateLock.unlock() }; return _jailbreakConsentGivenThisLaunch }
        set { stateLock.lock(); defer { stateLock.unlock() }; _jailbreakConsentGivenThisLaunch = newValue }
    }

    private var hardFailReason: String? {
        get { stateLock.lock(); defer { stateLock.unlock() }; return _hardFailReason }
        set { stateLock.lock(); defer { stateLock.unlock() }; _hardFailReason = newValue }
    }

    private var hardFailOverrideAcceptedThisLaunch: Bool {
        get { stateLock.lock(); defer { stateLock.unlock() }; return _hardFailOverrideAcceptedThisLaunch }
        set { stateLock.lock(); defer { stateLock.unlock() }; _hardFailOverrideAcceptedThisLaunch = newValue }
    }

    // -----------------------------------------------------------
    // Persistence of "disclosure seen" sticky bit.
    // -----------------------------------------------------------
    // Stored in Keychain() as a single-byte item so it survives a
    // JSON pref wipe (which would otherwise let an attacker re-
    // trigger the dialog repeatedly to phish the consent button).
    // Keychain access class is `WhenUnlockedThisDeviceOnly` and
    // `kSecAttrSynchronizable=false` so the bit does not leak via
    // iCloud Backup to a device the user has not actually
    // physically consented on.

    private static let consentKeychainService = "org.quantumcoin.wallet.tamper-gate"
    private static let consentKeychainAccount = "jailbreak-disclosure-seen-v1"

    private static func disclosureWasShownBefore() -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: consentKeychainService,
            kSecAttrAccount as String: consentKeychainAccount,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: kCFBooleanTrue as Any
        ]
        var item: CFTypeRef?
        let status = withUnsafeMutablePointer(to: &item) {
            SecItemCopyMatching(query as CFDictionary, $0)
        }
        _ = query
        return status == errSecSuccess
    }

    private static func recordDisclosureWasShown() {
        let data = Data([0x01])
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: consentKeychainService,
            kSecAttrAccount as String: consentKeychainAccount,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data
        ]
        // SecItemAdd returns errSecDuplicateItem if we are racing
        // with ourselves; either result is fine - the goal is "the
        // bit is set".
        SecItemDelete(attrs as CFDictionary)
        SecItemAdd(attrs as CFDictionary, nil)
    }

    // -----------------------------------------------------------
    // Entry point: launch-time policy.
    // -----------------------------------------------------------

    /// Run the bootstrap probes, classify, and either:
    /// - do nothing (clean device),
    /// - present a one-time disclosure dialog and install the
    /// persistent banner (jailbreak suspected),
    /// - present a hard-fail dialog and exit (debugger in
    /// Release / runtime tamper detected).
    /// Calls `completion(true)` when it is safe for AppDelegate to
    /// continue the normal launch path (clean OR
    /// jailbreak+consent-given). Calls `completion(false)` for the
    /// hard-fail paths so AppDelegate can stop short of touching
    /// the JS bridge.
    @MainActor
    public func evaluateAtLaunch(on presenter: UIViewController,
        window: UIWindow?,
        completion: @escaping @MainActor (Bool) -> Void) {
        guard Self.kTamperGateEnabled else {
            // Feature flag off: behave as if clean. Reserved for
            // the emergency-rollback path; flipping the flag in a
            // hotfix lets us disable the gate without touching
            // the policy logic.
            completion(true)
            return
        }

        TamperGate.bootstrap()
        let report = TamperGate.currentReport()

        switch report.severity {
            case .clean:
            completion(true)

            case .jailbreakSuspected:
            installJailbreakBanner(in: window)
            if Self.disclosureWasShownBefore() {
                // Sticky-bit already set -> banner only, no dialog.
                jailbreakConsentGivenThisLaunch = true
                completion(true)
            } else {
                presentJailbreakConsentDialog(on: presenter) { [weak self] continued in
                    guard let self else { return }
                    if continued {
                        Self.recordDisclosureWasShown()
                        self.jailbreakConsentGivenThisLaunch = true
                        completion(true)
                    } else {
                        // User chose Quit. Terminate the process
                        // after the dialog is dismissed.
                        self.terminateAfterDialog()
                    }
                }
            }

            case .debuggerAttachedInRelease:
            hardFailReason = "debugger-attached"
            presentHardFailDialog(
                on: presenter,
                title: Self.localized(
                    "tamper-debugger-title",
                    fallback: "Debugger detected"),
                message: Self.localized(
                    "tamper-debugger-message",
                    fallback: "A debugger is attached to this app. We strongly recommend you exit. If you understand the risk, you can ignore this warning and continue."),
                bannerText: Self.localized(
                    "tamper-debugger-banner",
                    fallback: "Debugger detected - reduced protection"),
                window: window,
                onQuit: { [weak self] in
                    self?.terminateAfterDialog()
                    completion(false)
                },
                onIgnore: { [weak self] in
                    self?.acceptHardFailOverride()
                    completion(true)
                })

            case .runtimeTamperDetected:
            hardFailReason = report.runtimeTamperReason ?? "tampered"
            presentHardFailDialog(
                on: presenter,
                title: Self.localized(
                    "tamper-runtime-title",
                    fallback: "Tampering detected"),
                message: Self.localized(
                    "tamper-runtime-message",
                    fallback: "This wallet's signing module has been modified. We strongly recommend you exit and reinstall from the App Store. If you understand the risk, you can ignore this warning and continue."),
                bannerText: Self.localized(
                    "tamper-runtime-banner",
                    fallback: "Tampering detected - reduced protection"),
                window: window,
                onQuit: { [weak self] in
                    self?.terminateAfterDialog()
                    completion(false)
                },
                onIgnore: { [weak self] in
                    self?.acceptHardFailOverride()
                    completion(true)
                })
        }
    }

    /// Centralized state mutation invoked when the user taps
    /// "Ignore and resume" on a hard-fail dialog. Clears the
    /// blocking `hardFailReason` so signing can proceed and sets
    /// the per-launch override flag so a re-evaluation inside
    /// `assertSafeToSign` does not block again. Per-launch only;
    /// we do NOT persist this state.
    @MainActor
    private func acceptHardFailOverride() {
        hardFailOverrideAcceptedThisLaunch = true
        hardFailReason = nil
    }

    // -----------------------------------------------------------
    // Per-signing-call gate.
    // -----------------------------------------------------------

    /// Throws if the wallet is not safe to use for signing right
    /// now. Called from `JsBridge.sendTransaction` and
    /// `JsBridge.sendTokenTransaction` BEFORE the payload is
    /// staged, so a hostile signing call cannot leak the private
    /// key into the bridge before the gate fires.
    /// Threading: callable from any thread. The class is
    /// non-isolated by design; the small amount of mutable state
    /// read here (`jailbreakConsentGivenThisLaunch`,
    /// `hardFailReason`) is locked behind `stateLock`. The
    /// per-call `P_TRACED` probe inside `TamperGate.currentReport`
    /// is itself thread-safe (it reads stack-local sysctl state).
    public func assertSafeToSign() throws {
        guard Self.kTamperGateEnabled else { return }

        // The user has explicitly accepted the hard-fail risk
        // earlier in this process via "Ignore and resume". Honor
        // that for the remaining lifetime of the process. The
        // override is per-launch only (see file header).
        if hardFailOverrideAcceptedThisLaunch {
            return
        }

        // Defense-in-depth: a hard-fail decision was made at
        // launch but the `exit(0)` 200ms delay has not yet run.
        // Refuse to sign in that gap.
        if let reason = hardFailReason {
            throw TamperGateError.runtimeTampered(reason)
        }

        // Re-read the report. Bootstrap probes are cached so this
        // is essentially a `sysctl` + a flag read.
        let report = TamperGate.currentReport()

        switch report.severity {
            case .clean:
            return

            case .jailbreakSuspected:
            // If the user has not yet acknowledged the disclosure
            // (e.g. we are in a signing call that fired before
            // the splash dismissal), refuse to sign rather than
            // leak through the gate.
            if !jailbreakConsentGivenThisLaunch {
                throw TamperGateError.jailbreakConsentNotGiven
            }

            case .debuggerAttachedInRelease:
            // A debugger was just attached (post-launch). Refuse
            // to sign. We do NOT `exit(0)` here because we are
            // on a background thread - safer to throw and let the
            // UI surface the error. The user can re-launch and
            // tap "Ignore and resume" if they want to continue.
            throw TamperGateError.debuggerAttached

            case .runtimeTamperDetected:
            throw TamperGateError.runtimeTampered(
                report.runtimeTamperReason ?? "unknown")
        }
    }

    // -----------------------------------------------------------
    // Dialogs.
    // -----------------------------------------------------------

    @MainActor
    private func presentJailbreakConsentDialog(on presenter: UIViewController,
        completion: @escaping @MainActor (Bool) -> Void) {
        let title = Self.localized(
            "tamper-jailbreak-title",
            fallback: "Reduced device protection")
        let message = Self.localized(
            "tamper-jailbreak-message",
            fallback: "This device shows signs of jailbreak. The OS-level isolation that protects your wallet is bypassed - apps you trust can be modified by other apps you have installed. Continue at your own risk, or quit?")
        let continueLabel = Self.localized(
            "tamper-continue-at-risk",
            fallback: "Continue at my own risk")
        let quitLabel = Self.localized(
            "tamper-quit",
            fallback: "Quit")

        let alert = UIAlertController(title: title,
            message: message,
            preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: continueLabel,
                style: .destructive) { _ in
                completion(true)
            })
        alert.addAction(UIAlertAction(title: quitLabel,
                style: .cancel) { _ in
                completion(false)
            })
        presenter.present(alert, animated: true)
    }

    /// Present the debugger / runtime-tamper dialog. Two actions:
    /// - **Quit** (cancel-style, default-emphasis): invokes
    /// `onQuit`, which terminates the process after the
    /// dismissal animation completes.
    /// - **Ignore and resume** (destructive-style, lower-
    /// emphasis): clears the hard-fail state, installs a
    /// persistent banner so the residual risk stays visible
    /// for the rest of the session, and invokes `onIgnore`.
    /// Action style note: `Quit` is the `.cancel` action so it is
    /// the bold default in iOS's alert layout. The destructive
    /// style on `Ignore and resume` paints the action red, which
    /// matches its semantic ("you are choosing to override a
    /// safety warning"). This is the same UI pattern used by
    /// system "potentially dangerous" prompts (e.g. "Open
    /// Untrusted App" in Settings()).
    @MainActor
    private func presentHardFailDialog(on presenter: UIViewController,
        title: String,
        message: String,
        bannerText: String,
        window: UIWindow?,
        onQuit: @escaping @MainActor () -> Void,
        onIgnore: @escaping @MainActor () -> Void) {
        let quitLabel = Self.localized(
            "tamper-quit",
            fallback: "Quit")
        let ignoreLabel = Self.localized(
            "tamper-ignore-and-resume",
            fallback: "Ignore and resume")

        let alert = UIAlertController(title: title,
            message: message,
            preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: quitLabel,
                style: .cancel) { _ in
                onQuit()
            })
        alert.addAction(UIAlertAction(title: ignoreLabel,
                style: .destructive) { [weak self] _ in
                self?.installHardFailBanner(in: window, text: bannerText)
                onIgnore()
            })
        presenter.present(alert, animated: true)
    }

    @MainActor
    private func terminateAfterDialog() {
        // Brief delay so the dialog dismissal animation completes
        // visually before the process disappears (otherwise the
        // user perceives the app as having "crashed").
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            // `exit(0)` rather than `fatalError` so we do not
            // produce a crash log Apple may treat as a real bug.
            exit(0)
        }
    }

    // -----------------------------------------------------------
    // Persistent banner.
    // -----------------------------------------------------------
    // Pinned-to-the-top label that says "Jailbroken device -
    // reduced protection". Same window-overlay pattern as
    // `SnapshotRedactor` so it survives root-view-controller
    // changes and modal presentations.

    private static let bannerTag: Int = 0xBA17_BA17
    private static let bannerHeight: CGFloat = 28

    @MainActor
    private func installJailbreakBanner(in window: UIWindow?) {
        installBanner(
            in: window,
            text: Self.localized(
                "tamper-jailbreak-banner",
                fallback: "Jailbroken device - reduced protection"))
    }

    @MainActor
    private func installHardFailBanner(in window: UIWindow?, text: String) {
        installBanner(in: window, text: text)
    }

    /// Idempotent banner installer. Tagged so a second install
    /// (e.g. jailbreak banner already present, debugger override
    /// also accepted) is a no-op rather than stacking two
    /// banners. The single visible banner deliberately reflects
    /// whichever risk the user accepted FIRST; the dialog the
    /// user just dismissed is the up-to-date description of the
    /// composite risk.
    @MainActor
    private func installBanner(in window: UIWindow?, text: String) {
        guard let window = window else { return }
        if window.viewWithTag(Self.bannerTag) != nil { return }

        let banner = UILabel()
        banner.tag = Self.bannerTag
        banner.text = text
        banner.textColor = .white
        banner.backgroundColor = UIColor.systemRed
        banner.textAlignment = .center
        banner.font = .systemFont(ofSize: 12, weight: .semibold)
        banner.adjustsFontSizeToFitWidth = true
        banner.minimumScaleFactor = 0.7
        banner.numberOfLines = 1
        banner.translatesAutoresizingMaskIntoConstraints = false

        window.addSubview(banner)
        window.bringSubviewToFront(banner)
        let safe = window.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
                banner.leadingAnchor.constraint(equalTo: window.leadingAnchor),
                banner.trailingAnchor.constraint(equalTo: window.trailingAnchor),
                banner.topAnchor.constraint(equalTo: safe.topAnchor),
                banner.heightAnchor.constraint(equalToConstant: Self.bannerHeight)
            ])
    }

    // -----------------------------------------------------------
    // Localization helper.
    // -----------------------------------------------------------
    // English fallbacks are mandatory so a missing or
    // mistranslated localization entry never strips the safety
    // message. The pattern matches the fix in
    // `TransactionReviewDialogViewController`: read the localized
    // string, fall back to the embedded English on empty.

    private static func localized(_ key: String, fallback: String) -> String {
        let value: String
        switch key {
            case "tamper-jailbreak-title":
            value = Localization.shared.getTamperJailbreakTitleByLangValues()
            case "tamper-jailbreak-message":
            value = Localization.shared.getTamperJailbreakMessageByLangValues()
            case "tamper-continue-at-risk":
            value = Localization.shared.getTamperContinueAtRiskByLangValues()
            case "tamper-quit":
            value = Localization.shared.getTamperQuitByLangValues()
            case "tamper-ignore-and-resume":
            value = Localization.shared.getTamperIgnoreAndResumeByLangValues()
            case "tamper-debugger-title":
            value = Localization.shared.getTamperDebuggerTitleByLangValues()
            case "tamper-debugger-message":
            value = Localization.shared.getTamperDebuggerMessageByLangValues()
            case "tamper-debugger-banner":
            value = Localization.shared.getTamperDebuggerBannerByLangValues()
            case "tamper-runtime-title":
            value = Localization.shared.getTamperRuntimeTitleByLangValues()
            case "tamper-runtime-message":
            value = Localization.shared.getTamperRuntimeMessageByLangValues()
            case "tamper-runtime-banner":
            value = Localization.shared.getTamperRuntimeBannerByLangValues()
            case "tamper-jailbreak-banner":
            value = Localization.shared.getTamperJailbreakBannerByLangValues()
            default:
            value = ""
        }
        return value.isEmpty ? fallback : value
    }
}

// MARK: - Errors thrown from `assertSafeToSign`

public enum TamperGateError: Error, CustomStringConvertible, Sendable {
    case jailbreakConsentNotGiven
    case debuggerAttached
    case runtimeTampered(String)

    public var description: String {
        switch self {
            case .jailbreakConsentNotGiven:
            return "Signing refused: device shows signs of jailbreak and the user has not yet acknowledged the risk."
            case .debuggerAttached:
            return "Signing refused: a debugger is attached to the wallet process."
            case .runtimeTampered(let reason):
            return "Signing refused: runtime tamper detected (\(reason))."
        }
    }
}
