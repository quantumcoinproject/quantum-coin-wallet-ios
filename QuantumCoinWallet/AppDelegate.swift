//
// AppDelegate.swift
//
// Mirrors `HomeActivity.onCreate` + `QuantumCoinWalletApp.onCreate`:
// initialize the JS bridge, await readiness, run the
// `loadSeedsThread` equivalent (initializeOffline + getAllSeedWords),
// populate the seed-word lookup tables, then build the UI.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/view/activities/HomeActivity.java
//

import UIKit

@main
public final class AppDelegate: UIResponder, UIApplicationDelegate {

    public var window: UIWindow?

    public func application(_ application: UIApplication,
                            didFinishLaunchingWithOptions
                              launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

        _ = Localization.shared
        _ = PrefConnect.shared

        let window = UIWindow(frame: UIScreen.main.bounds)
        self.window = window
        let splash = SplashViewController()
        window.rootViewController = splash
        window.makeKeyAndVisible()

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
                await MainActor.run { splash.show(message: "Bridge not ready") }
                return
            }
            do {
                try await Bootstrap.loadSeedsThreadEquivalent()
                await MainActor.run {
                    // One-shot privacy migration: drop the legacy
                    // plaintext INDEX_ADDRESS / ADDRESS_INDEX maps and
                    // the legacy plaintext BLOCKCHAIN_NETWORK_LIST /
                    // BLOCKCHAIN_NETWORK_ID_INDEX_KEY entries from the
                    // JSON pref file, plus the predecessor encrypted
                    // SECURE_ADDRESS_INDEX_MAP blob. The combined
                    // SECURE_VAULT_BLOB (created on first unlock from
                    // those legacy sources - see
                    // KeyStore.rebuildVaultState) is now the only
                    // place address rows + custom networks live on
                    // disk.
                    //
                    // We run this AFTER the JS bridge is ready and
                    // BEFORE HomeViewController so that the launch
                    // gate's first unlock has a chance to seed the
                    // vault blob BEFORE the plaintext copies are
                    // wiped. The function is idempotent and gated on
                    // SECURE_VAULT_BLOB existence; KeyStore.unlock
                    // also calls it, so the first successful unlock
                    // completes the migration within the same launch.
                    PrefConnect.shared.runPrivacyMigrationV1IfNeeded()
                    SessionLock.shared.start()
                    let root = HomeViewController()
                    window.rootViewController = root
                }
            } catch {
                await MainActor.run { splash.show(message: "Bootstrap failed: \(error)") }
            }
        }

        return true
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
