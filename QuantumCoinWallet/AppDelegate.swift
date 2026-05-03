// AppDelegate.swift
// Mirrors `HomeActivity.onCreate` + `QuantumCoinWalletApp.onCreate`:
// initialize the JS bridge, await readiness, run the
// `loadSeedsThread` equivalent (initializeOffline + getAllSeedWords),
// populate the seed-word lookup tables, then build the UI.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/activities/HomeActivity.java

import UIKit

@main
public final class AppDelegate: UIResponder, UIApplicationDelegate {

    public var window: UIWindow?

    public func application(_ application: UIApplication,
        didFinishLaunchingWithOptions
        launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

        _ = Localization.shared
        _ = PrefConnect.shared

        // Sweep any leftover staged backup files in
        // `tmp/` from a prior export that crashed / was killed before
        // the picker delegate could clean up. The sweep is targeted
        // (only directories matching `qcw-backup-*`) and is safe to
        // run on the main thread because it's a single
        // `contentsOfDirectory` + filtered `removeItem` over the app's
        // own tmp directory. Doing this here at launch (rather than
        // lazily on first export) means a malicious sibling cannot
        // see the leftover files even if they get a chance to read
        // before the user opens the app's first backup screen.
        CloudBackupManager.shared.cleanupStaleStagedExports()

        // Register the app-switcher snapshot
        // redaction overlay BEFORE the first `willResignActive` can
        // fire, so the very first background transition produces a
        // branded card rather than a screenshot of whatever was on
        // screen (worst case: the seed-words / Reveal screen). See
        // SnapshotRedactor.swift for the full rationale and the
        // tradeoffs.
        SnapshotRedactor.shared.install()

        let window = UIWindow(frame: UIScreen.main.bounds)
        self.window = window
        let splash = SplashViewController()
        window.rootViewController = splash
        window.makeKeyAndVisible()

        // Verify the JS bundle's SHA-256 matches
        // the build-time embedded constant BEFORE the JsEngine
        // creates the WKWebView. The bundle owns every signing
        // primitive in the wallet; a tampered bundle silently
        // changes signing behaviour. The verifier reads the same
        // file the WKURLSchemeHandler will serve, hashes it, and
        // throws on mismatch. We surface the failure as a
        // permanent splash-screen message rather than crashing
        // because:
        // - "App crashed at launch" looks like a normal bug to
        // the user; a visible "tamper detected" message is
        // audit-grade observable.
        // - The wallet must NOT proceed to onboarding on a
        // tampered bundle, so we do not call `JsEngine.shared`
        // or `BlockchainNetworkManager.bootstrap` below.
        // A second, defense-in-depth verification fires inside
        // `AppAssetsSchemeHandler.webView(_:start:)` when the
        // `WKURLSchemeHandler` is asked for the bundle bytes; the
        // serving-time check catches the (theoretical) case where
        // the on-disk bytes change between boot and bundle load.
        do {
            try BundleIntegrity.verifyOrFail()
        } catch {
            splash.show(message: "Tamper detected: refusing to start. \(error)")
            return true
        }

        // Run the layered TamperGate probes
        // (jailbreak / debugger-in-Release / runtime tamper) and
        // route by severity:
        // .clean -> proceed normally below.
        // .jailbreakSuspected -> one-time disclosure
        // dialog + persistent
        // banner; user can
        // continue or quit.
        // .debuggerAttachedInRelease -> hard-fail dialog ->
        // exit(0).
        // .runtimeTamperDetected -> hard-fail dialog ->
        // exit(0).
        // The probe layer is in `Security/TamperGate.swift`; the
        // policy + UI layer (this call site) is in
        // `Security/TamperGatePolicy.swift`. The split keeps the
        // probes unit-testable and keeps every UI-facing decision
        // in one reviewable place.
        // Bootstrap MUST run on the main actor because a subset
        // of the jailbreak probes (URL-scheme handlers) calls
        // `UIApplication.canOpenURL`, which is MainActor-isolated.
        // We are inside `application(_:didFinishLaunchingWithOptions:)`
        // here, which is already MainActor.
        // The completion handler is dispatched synchronously for
        // the clean case and synchronously after the user dismisses
        // the disclosure dialog for the jailbreak case. The hard-
        // fail cases call completion(false) immediately after
        // showing their dialog, but the actual `exit(0)` happens
        // on a 200ms delay so the dialog dismissal animation
        // completes visually before the process disappears -
        // otherwise the user perceives a "crash".
        TamperGatePolicy.shared.evaluateAtLaunch(on: splash, window: window) {
            ok in
            guard ok else { return }
            self.continueLaunchAfterTamperGate(window: window, splash: splash)
        }

        return true
    }

    /// Continuation of the launch flow after `TamperGate` decides
    /// the wallet may proceed. Extracted so the AppDelegate's main
    /// entry point reads top-down rather than nesting this body
    /// inside the gate's completion closure.
    private func continueLaunchAfterTamperGate(window: UIWindow,
        splash: SplashViewController) {
        // Force `JsEngine.shared` to initialise on the main thread
        // BEFORE anything that could schedule a background task that
        // touches `JsEngine.shared` (e.g. `BlockchainNetworkManager`'s
        // `applyActive` -> `Task.detached { JsBridge.initialize(...) }`).
        // `JsEngine` is `@MainActor` isolated and its `init` constructs
        // a `WKWebView`, which traps on non-main threads. Without this
        // ordering the detached task can win the race to the lazy init
        // and crash inside `createWebView`.
        _ = JsEngine.shared

        // Bootstrap blockchain networks AFTER JsEngine exists, so the
        // detached `JsBridge.initialize` task spawned by `applyActive`
        // sees an already-constructed engine and only reads its
        // `nonisolated` API surface from the background thread.
        BlockchainNetworkManager.shared.bootstrap()

        Task.detached(priority: .userInitiated) {
            let ready = await JsEngine.shared.waitUntilReady(timeout: 30)
            guard ready else {
                // Surface the real reason if the WKNavigationDelegate
                // captured one (added in JsEngine for the missing
                // didFail* / process-terminate paths). Falling back to
                // the legacy generic message preserves behaviour when
                // the failure was a genuine timeout (no delegate
                // callback ever fired).
                let detail = JsEngine.shared.lastLoadFailureDescription
                ?? "Bridge WebView did not finish loading within 30s."
                await MainActor.run { splash.show(message: "Bridge not ready: \(detail)") }
                return
            }
            // The latch can also be signalled by a load failure
            // (didFailProvisionalNavigation et al.). In that case
            // `isReady` is false even though `waitUntilReady`
            // returned `true`. Bail out with the captured failure
            // before trying to call into the bridge.
            if !JsEngine.shared.isReady {
                let detail = JsEngine.shared.lastLoadFailureDescription
                ?? "Bridge load failed for an unknown reason."
                await MainActor.run { splash.show(message: "Bridge not ready: \(detail)") }
                return
            }
            do {
                try await Bootstrap.loadSeedsThreadEquivalent()
                await MainActor.run {
                    // Boot-time housekeeping for the strongbox slot
                    // files: clean up any leftover .tmp from a prior
                    // crashed write (see AtomicSlotWriter file
                    // header), and re-apply the user's "Phone
                    // Backup" preference to the slot files'
                    // isExcludedFromBackupKey resource value (see
                    // BackupExclusion.swift).
                    AtomicSlotWriter.shared.cleanupTempFiles()
                    BackupExclusion.applyToStrongboxFiles()
                    SessionLock.shared.start()
                    let root = HomeViewController()
                    window.rootViewController = root
                }
            } catch {
                await MainActor.run { splash.show(message: "Bootstrap failed: \(error)") }
            }
        }
    }

    public func applicationDidBecomeActive(_ application: UIApplication) {
        SessionLock.shared.applicationDidBecomeActive()
    }

    public func applicationWillResignActive(_ application: UIApplication) {
        SessionLock.shared.applicationWillResignActive()
    }
}

// MARK: - Bootstrap

public enum Bootstrap {

    /// Port of `HomeActivity.loadSeedsThread`: call `initializeOffline`,
    /// fetch the BIP-39 word list via the JS SDK, populate the global
    /// lookup tables used by the seed-verify autocomplete.
    public static func loadSeedsThreadEquivalent() async throws {
        _ = try await JsBridge.shared.initializeOfflineAsync()
        let seedsEnvelope = try await JsBridge.shared.getAllSeedWordsAsync()
        let words = try Self.parseAllSeedWords(seedsEnvelope)
        await MainActor.run {
            BIP39Words.setAll(words)
        }
    }

    /// Bridge envelope contract (`{"success":true,"data":{"words":[...]}}`).
    /// See `bridge.html` `sendResult`.
    private static func parseAllSeedWords(_ envelope: String) throws -> [String] {
        guard let data = envelope.data(using: .utf8),
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw NSError(domain: "Bootstrap", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "seeds envelope not JSON"])
        }
        let wordsAny: Any? = (obj["data"] as? [String: Any])?["words"]
        ?? obj["words"]
        if let arr = wordsAny as? [String] { return arr }
        if let s = wordsAny as? String, let d = s.data(using: .utf8),
        let arr = try? JSONSerialization.jsonObject(with: d) as? [String] {
            return arr
        }
        throw NSError(domain: "Bootstrap", code: 2,
            userInfo: [NSLocalizedDescriptionKey: "seed words list missing"])
    }
}

// MARK: - Splash

final class SplashViewController: UIViewController {

    private let label = UILabel()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorPrimaryDark") ?? .systemBackground
        label.text = "Loading..."
        label.textColor = .white
        label.font = Typography.mediumLabel(14)
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
                label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
                label.centerYAnchor.constraint(equalTo: view.centerYAnchor)
            ])
    }

    func show(message: String) { label.text = message }
}
