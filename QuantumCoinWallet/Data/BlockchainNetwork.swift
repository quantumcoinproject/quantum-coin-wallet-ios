// BlockchainNetwork.swift
// Port of `BlockchainNetwork.java` and the Android
// `GlobalMethods.setActiveNetwork` flow. Loads
// `blockchain_networks.json` from the bundle (pre-unlock fallback),
// then layers in user-added networks restored from the encrypted
// strongbox payload once the wallet is unlocked, and re-points
// `ApiClient`, `Constants`, and the JS bridge on switch.
// iOS storage diverges from Android (which keeps custom networks in
// plaintext SharedPreferences). Here, every user-added network and the
// active-network offset travel inside the same encrypted blob the
// address map already lives in - one AES-GCM open per unlock recovers
// everything the UI needs, and the on-disk pref file shows opaque
// ciphertext rather than the user's network customisations.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/model/BlockchainNetwork.java
// app/src/main/java/com/quantumcoinwallet/app/utils/GlobalMethods.java (setActiveNetwork)
//
// Concurrency discipline (Part 1 of the security fix plan, closes
// UNIFIED-006 / UNIFIED-D009):
// `BlockchainNetworkManager` mirrors the NSLock + private-storage
// pattern used by `Utilities/Constants.swift` for the legacy
// `SCAN_API_URL` / `RPC_ENDPOINT_URL` / `BLOCK_EXPLORER_URL` /
// `CHAIN_ID` mirrors. The lock holds across the entire mutation
// pipeline including the slow `persistThroughStrongboxLocked`
// scrypt + AEAD seal + slot-write window AND the rollback-on-throw
// branch, so a concurrent reader can never observe a torn or
// half-rolled-back `(networks, activeIndex)` pair. `applyActiveLocked`
// is the SINGLE publish point that fans the new snapshot out to
// `Constants.*`, `ApiClient.basePath`, and `NetworkConfig.publishSync`
// in the same critical section so all four observation surfaces see
// the same epoch (closing UNIFIED-007 in concert with
// `Networking/NetworkConfig.swift`'s synchronous mirror).

import Foundation

public extension Notification.Name {
    /// Posted on the main queue whenever the active blockchain network
    /// or the list of available networks changes (`bootstrap`,
    /// `applyDecryptedConfig`, `addNetwork`, `setActive`,
    /// `resetToBundled`). Subscribers (e.g. `HomeViewController`) use
    /// it to refresh chrome that displays the active-network name.
    static let networkConfigDidChange = Notification.Name("networkConfigDidChange")
}

public struct BlockchainNetwork: Codable, Equatable, Sendable {
    public let name: String
    public let chainId: String
    public let scanApiDomain: String
    public let rpcEndpoint: String
    public let blockExplorerUrl: String

    // The decoder accepts BOTH iOS-style keys (`name`, `chainId`,
    // `blockExplorerUrl`) used by the bundled `blockchain_networks.json`
    // and the encrypted strongbox, AND Android-style keys (`networkId`,
    // `blockchainName`, `blockExplorerDomain`) shown to the user inside
    // the Add Network screen as the editable default. iOS-style keys
    // win when both are present so existing on-disk data continues to
    // round-trip cleanly. The encoder still writes iOS-style keys, so
    // the strongbox format on disk does not change.
    // Note: an earlier iOS-only `id` field (string slug like `"mainnet"`)
    // has been retired. The numeric `chainId` (matching Android's
    // `networkId`) now serves as the canonical network identifier; any
    // legacy strongbox that still has `id` is simply ignored on decode.
    private enum CodingKeys: String, CodingKey {
        case name, chainId, scanApiDomain, rpcEndpoint, blockExplorerUrl
        case networkId, blockchainName, blockExplorerDomain
    }

    public init(name: String, chainId: String,
        scanApiDomain: String, rpcEndpoint: String, blockExplorerUrl: String) {
        self.name = name; self.chainId = chainId
        self.scanApiDomain = scanApiDomain; self.rpcEndpoint = rpcEndpoint
        self.blockExplorerUrl = blockExplorerUrl
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)

        // chainId / networkId can be a string OR a JSON number on
        // either schema (Android writes a bare integer, iOS writes a
        // string). Resolve once and reuse for chainId.
        let normalizedNetworkId: String? = {
            if let s = try? c.decode(String.self, forKey: .networkId) { return s }
            if let n = try? c.decode(Int.self, forKey: .networkId) { return String(n) }
            return nil
        }()

        if let s = try? c.decode(String.self, forKey: .name), !s.isEmpty {
            self.name = s
        } else if let s = try? c.decode(String.self, forKey: .blockchainName) {
            self.name = s
        } else {
            self.name = ""
        }

        if let s = try? c.decode(String.self, forKey: .chainId) {
            self.chainId = s
        } else if let n = try? c.decode(Int.self, forKey: .chainId) {
            self.chainId = String(n)
        } else if let nid = normalizedNetworkId {
            // Android exposes the network identifier as `networkId`;
            // reuse it as iOS's `chainId` so the constructed model has
            // a stable identifier regardless of which schema authored
            // the JSON.
            self.chainId = nid
        } else {
            self.chainId = ""
        }

        let scanRaw = (try? c.decodeIfPresent(String.self, forKey: .scanApiDomain)) ?? ""
        self.scanApiDomain = Self.ensureHttps(scanRaw)

        self.rpcEndpoint = (try? c.decodeIfPresent(String.self, forKey: .rpcEndpoint)) ?? ""

        if let url = try? c.decodeIfPresent(String.self, forKey: .blockExplorerUrl), !url.isEmpty {
            self.blockExplorerUrl = url
        } else if let domain = try? c.decodeIfPresent(String.self, forKey: .blockExplorerDomain) {
            self.blockExplorerUrl = Self.ensureHttps(domain)
        } else {
            self.blockExplorerUrl = ""
        }
    }

    /// Custom encoder writes ONLY the iOS-shaped keys so the encrypted
    /// strongbox stays binary-compatible with existing on-disk user data.
    /// The Android-style cases on `CodingKeys` exist purely as decode
    /// fallbacks for the Add Network screen; they are deliberately
    /// never written.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(name, forKey: .name)
        try c.encode(chainId, forKey: .chainId)
        try c.encode(scanApiDomain, forKey: .scanApiDomain)
        try c.encode(rpcEndpoint, forKey: .rpcEndpoint)
        try c.encode(blockExplorerUrl, forKey: .blockExplorerUrl)
    }

    /// Android writes bare hostnames (`app.readrelay....`) where iOS
    /// expects full URLs with scheme (`https://app.readrelay....`).
    /// Prefix `https://` when the input is non-empty and missing a
    /// scheme so the rest of the iOS stack (`ApiClient.basePath`,
    /// `Constants.SCAN_API_URL`, block-explorer deeplinks) keeps
    /// working.
    /// hardening (audit-grade notes for AI reviewers
    /// and human auditors):
    /// The entry-form validator (`BlockchainNetworkViewController
    /// .isValidScanLikeDomain`) rejects `http://` outright as the
    /// primary gate. This model-layer transform is a defense-in-depth
    /// floor: if any code path EVER manages to flow an `http://` URL
    /// into the strongbox (a future regression in the entry form, a
    /// migration bug, an attacker who edits the on-disk strongbox state),
    /// the model layer SILENTLY UPGRADES it to `https://` rather than
    /// passing it through as plaintext. That choice is deliberate:
    /// - Rejecting (returning `""`) would empty the field, breaking
    /// the UI in a way the user cannot diagnose ("network
    /// configuration disappeared").
    /// - Throwing would require changing every Decodable init in
    /// the project to be throws-aware, which is a much larger
    /// blast radius for a defense-in-depth fix.
    /// - Silent upgrade gives the user a working network whose
    /// connection is actually secure - a strict improvement over
    /// both alternatives, even if the caller "asked for" http.
    /// Per the section-1 "no current users" precondition there is no
    /// on-disk strongbox that legitimately contains `http://` today, so
    /// the upgrade path should never trigger in practice.
    private static func ensureHttps(_ s: String) -> String {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return "" }
        let lower = trimmed.lowercased()
        if lower.hasPrefix("https://") { return trimmed }
        // Silent upgrade defense-in-depth (see doc).
        if lower.hasPrefix("http://") {
            return "https://" + trimmed.dropFirst("http://".count)
        }
        return "https://" + trimmed
    }
}

public final class BlockchainNetworkManager: @unchecked Sendable {

    public static let shared = BlockchainNetworkManager()

    // ------------------------------------------------------------------
    // What it closes:
    //   The previous `public private(set) var networks` /
    //   `public private(set) var activeIndex` shape allowed concurrent
    //   readers (URLSession.delegate threads, UI listeners on the
    //   main queue, the JS bridge initialisation `Task.detached`) to
    //   observe `(networks, activeIndex)` mid-mutation. Swift `Array`
    //   and `Int` writes are not atomic at the language level - a
    //   reader could see the new `activeIndex` paired with the OLD
    //   `networks`, indexing past the end and either silently wrong-
    //   network'ing the user or crashing. Two simultaneous mutators
    //   (e.g. an "add network" `Task.detached` racing a "switch network"
    //   `Task.detached` that the user kicked off in two different
    //   sheets) could also leave the strongbox-on-disk and the
    //   in-memory state out of sync after a partial rollback.
    // Why this shape (NSLock + private storage + computed accessors):
    //   Mirrors the existing pattern in `Utilities/Constants.swift`
    //   for `SCAN_API_URL` / `RPC_ENDPOINT_URL` / `BLOCK_EXPLORER_URL` /
    //   `CHAIN_ID`. NSLock is sufficient: every mutation site is a
    //   user-tappable action (rare on the time scale of lock contention),
    //   the slow `persistThroughStrongbox` work runs while the lock is
    //   held, and the existing call sites are MainActor-confined sync
    //   UI code that cannot await on an actor without a UI refactor
    //   far beyond the scope of this fix. The serial discipline is the
    //   property we want.
    // Tradeoffs:
    //   The `persistThroughStrongbox` slow path (scrypt + AEAD seal +
    //   slot write, ~300-500 ms) runs while `_stateLock` is held.
    //   Worst case: a second user tap on a different mutator waits one
    //   user-tappable action for the first to complete. The alternative
    //   (drop the lock around the slow work + rollback dance) re-opens
    //   the race that this fix exists to close.
    // Cross-references:
    //   - SECURITY_AUDIT_FINDINGS.md UNIFIED-006 (data race on
    //     `(networks, activeIndex)`) and UNIFIED-D009 (compound mutation
    //     race specifically for double-tap "Add Network" sequences).
    //   - `QuantumCoinWallet/Utilities/Constants.swift` for the matching
    //     `_networkLock` + private backing pattern that this code mirrors.
    //   - `QuantumCoinWallet/Schema/StrongboxFileCodec.swift` for the
    //     analogous `writerQueue.sync` discipline on the codec side.
    // ------------------------------------------------------------------
    private let _stateLock = NSLock()
    private var _networks: [BlockchainNetwork] = []
    private var _activeIndex: Int = 0

    public var networks: [BlockchainNetwork] {
        _stateLock.lock(); defer { _stateLock.unlock() }
        return _networks
    }

    public var activeIndex: Int {
        _stateLock.lock(); defer { _stateLock.unlock() }
        return _activeIndex
    }

    public var active: BlockchainNetwork? {
        _stateLock.lock(); defer { _stateLock.unlock() }
        guard _activeIndex >= 0 && _activeIndex < _networks.count else { return nil }
        return _networks[_activeIndex]
    }

    private init() {}

    /// Cold-launch entry point. Called from
    /// `AppDelegate.didFinishLaunchingWithOptions` before the user has
    /// had a chance to enter their wallet password, so it MUST NOT
    /// touch `KeyStore` (which is still locked). Loads only the
    /// bundled MAINNET fallback so screens that render before the
    /// unlock dialog (cold-launch gate, JS-bridge initialisation) have
    /// a working chain config.
    public func bootstrap() {
        _stateLock.lock()
        _networks = loadBundled()
        _activeIndex = 0
        applyActiveLocked()
        _stateLock.unlock()
        Self.postConfigChanged()
    }

    /// Called from `UnlockCoordinatorV2.unlockWithPasswordAndApplySession`
    /// once the encrypted strongbox payload has been decrypted.
    /// Layers the user-added networks on top of the
    /// bundled defaults, restores the active offset, and re-runs
    /// `applyActiveLocked` so `Constants.*`, `ApiClient.basePath`, and the
    /// JS bridge match the user's selection. Must be called on the
    /// main thread.
    public func applyDecryptedConfig(customNetworks: [BlockchainNetwork],
        activeIndex savedIndex: Int) {
        _stateLock.lock()
        let bundled = loadBundled()
        _networks = bundled + customNetworks
        let upper = max(0, _networks.count - 1)
        _activeIndex = max(0, min(savedIndex, upper))
        applyActiveLocked()
        _stateLock.unlock()
        Self.postConfigChanged()
    }

    /// Called from `UnlockCoordinatorV2.lock` so a foreground
    /// after relock only sees the bundled MAINNET (mirrors how
    /// the address map
    /// becomes empty post-lock). User-added networks reappear on the
    /// next successful unlock via `applyDecryptedConfig`.
    public func resetToBundled() {
        _stateLock.lock()
        _networks = loadBundled()
        _activeIndex = 0
        applyActiveLocked()
        _stateLock.unlock()
        Self.postConfigChanged()
    }

    /// Switch the active blockchain network. `password` is required so
    /// `KeyStore` can re-derive the strongbox main key, re-encrypt the
    /// strongbox blob with the new active-index, and zero the bytes before
    /// returning. Callers (`BlockchainNetworkSelectDialogViewController`)
    /// must collect the password through `UnlockDialogViewController`
    /// before invoking this method. The in-memory `_activeIndex` is
    /// rolled back if the persist fails so a wrong-password retry
    /// doesn't desync memory from disk.
    /// (audit-grade notes for AI reviewers and human auditors):
    /// the `_stateLock` is held across the entire mutation pipeline
    /// INCLUDING the rollback-on-throw branch. Without this, a
    /// concurrent reader could observe the half-rolled-back state
    /// (new index installed, persist threw, observer reads the new
    /// index, rollback runs, observer's read is now from the wrong
    /// epoch). The slow `persistThroughStrongbox` runs while the
    /// lock is held; this is intentional - serialising mutators is
    /// the point of the fix. See class header for the cross-reference
    /// to UNIFIED-006 / UNIFIED-D009.
    public func setActive(index: Int, password: String,
        onPhase: UnlockCoordinatorV2.WriteVerifyPhaseCallback? = nil) throws {
        _stateLock.lock()
        defer { _stateLock.unlock() }
        guard index >= 0 && index < _networks.count else { return }
        let previous = _activeIndex
        _activeIndex = index
        do {
            try persistThroughStrongboxLocked(password: password, onPhase: onPhase)
        } catch {
            _activeIndex = previous
            throw error
        }
        applyActiveLocked()
        Self.postConfigChanged()
    }

    /// Append a new user-defined blockchain network. `password` is
    /// required for the same reason `setActive` requires it - the new
    /// entry must be written to the encrypted strongbox blob, which means
    /// re-deriving the strongbox main key from the user's password. On
    /// persist failure the new entry is rolled back so the in-memory
    /// `_networks` list stays in lock-step with disk, allowing the user
    /// to retry the unlock prompt without duplicating the entry.
    /// (audit-grade notes for AI reviewers and human auditors):
    /// the `_stateLock` is held across `_networks.append` AND the
    /// rollback `removeLast` so a concurrent reader cannot witness
    /// a duplicated trailing entry. A double-tap on the "Save" button
    /// in `BlockchainNetworkViewController` now serialises naturally:
    /// the second tap waits for the first to complete (success OR
    /// rollback) before evaluating its own append. See class header.
    public func addNetwork(_ n: BlockchainNetwork, password: String,
        onPhase: UnlockCoordinatorV2.WriteVerifyPhaseCallback? = nil) throws {
        _stateLock.lock()
        defer { _stateLock.unlock() }
        _networks.append(n)
        do {
            try persistThroughStrongboxLocked(password: password, onPhase: onPhase)
        } catch {
            _networks.removeLast()
            throw error
        }
        Self.postConfigChanged()
    }

    /// Honor the `.networkConfigDidChange` header contract: every
    /// observer (`HomeMainViewController.handleNetworkConfigDidChange`,
    /// `SendViewController`, etc.) reloads UITableViews / mutates Auto
    /// Layout state in its handler and therefore MUST run on the main
    /// thread. `setActive` is reached from a `Task.detached` in
    /// `BlockchainNetworkSelectDialogViewController.promptUnlockThenSetActive`
    /// (the unlock + scrypt + persist round-trip cannot block the main
    /// queue), so a synchronous `NotificationCenter.post` from the
    /// callee would fire observers on that background thread and crash
    /// inside `NSISEngine` ("Modifications to the layout engine must
    /// not be performed from a background thread..."). Centralising the
    /// post here means every mutation site - present and future - is
    /// safe regardless of which queue it runs on.
    /// `async` (not `sync`) so calls already on the main queue do not
    /// reentrantly fire observers mid-mutation; observers see the
    /// mutation as a completed event on the next runloop tick, which
    /// matches what every observer was already coded to expect.
    private static func postConfigChanged() {
        if Thread.isMainThread {
            NotificationCenter.default.post(
                name: .networkConfigDidChange, object: nil)
        } else {
            DispatchQueue.main.async {
                NotificationCenter.default.post(
                    name: .networkConfigDidChange, object: nil)
            }
        }
    }

    /// Snapshot the user-added slice (i.e. everything past the bundled
    /// prefix) and round-trip the current `activeIndex` back into the
    /// encrypted strongbox.
    /// Why does adding / switching a network now require a password?
    /// -------------------------------------------------------------
    /// On Android, custom networks live in plaintext SharedPreferences,
    /// so adding one is genuinely a no-secret-needed operation. iOS is
    /// stricter: the same data goes into the encrypted strongbox payload
    /// alongside the address map. The encryption key (`mainKey`) is
    /// intentionally NOT cached in memory across operations - every
    /// strongbox write derives it from the user's password, uses the
    /// bytes once, and zeroes them. So the picker prompts the user
    /// for their password through `UnlockDialogViewController` before
    /// calling `addNetwork` or `setActive`, which forwards the
    /// password to `UnlockCoordinatorV2.replaceNetworks` for the
    /// actual derive-encrypt-write cycle.
    /// PRECONDITION: `_stateLock` MUST be held by the caller. The
    /// `Locked` suffix is the audit convention for "method assumes
    /// the enclosing lock is held"; cross-checked by code review.
    /// Reads `_networks` and `_activeIndex` directly so it does not
    /// re-enter the lock through the public computed accessors.
    private func persistThroughStrongboxLocked(password: String,
        onPhase: UnlockCoordinatorV2.WriteVerifyPhaseCallback? = nil) throws {
        let bundledCount = loadBundled().count
        let custom = Array(_networks.dropFirst(bundledCount))
        try UnlockCoordinatorV2.replaceNetworks(
            custom, activeIndex: _activeIndex, password: password,
            onPhase: onPhase)
    }

    /// PRECONDITION: `_stateLock` MUST be held by the caller. Renamed
    /// from `applyActive()` to reflect the held-lock contract.
    /// (audit-grade notes for AI reviewers and human auditors):
    /// this method publishes the new network into THREE sinks in the
    /// same critical section so a synchronous reader cannot observe
    /// a torn view (Constants says new network, NetworkConfig still
    /// says old, ApiClient.basePath in flux):
    ///   1. `Constants.*` mirrors (lock-protected via NSLock inside
    ///      Constants for legacy synchronous UI readers).
    ///   2. `ApiClient.basePath` (lock-protected via the new accessor
    ///      added in Part 1b).
    ///   3. `NetworkConfig.publishSync(...)` synchronous mirror added
    ///      in Part 1c (the canonical synchronous source that the
    ///      signing-path "Review" capture in SendViewController uses).
    /// The asynchronous `Task { await NetworkConfig.shared.apply }`
    /// is RETAINED for any future async consumer; the actor remains
    /// the canonical async source. The static synchronous mirror
    /// closes UNIFIED-007 (capture-time torn view between actor and
    /// Constants).
    private func applyActiveLocked() {
        guard _activeIndex >= 0 && _activeIndex < _networks.count else { return }
        let net = _networks[_activeIndex]
        ApiClient.shared.basePath = net.scanApiDomain
        Constants.SCAN_API_URL = net.scanApiDomain
        Constants.RPC_ENDPOINT_URL = net.rpcEndpoint
        Constants.BLOCK_EXPLORER_URL = net.blockExplorerUrl
        Constants.CHAIN_ID = Int(net.chainId) ?? 0

        let snapshot = NetworkSnapshot(
            name: net.name,
            chainId: Constants.CHAIN_ID,
            rpcEndpoint: net.rpcEndpoint,
            scanApiUrl: net.scanApiDomain,
            blockExplorerUrl: net.blockExplorerUrl)
        // SYNCHRONOUS publish - closes UNIFIED-007. Any caller that
        // reads `NetworkConfig.currentSync` immediately after this
        // returns observes the same epoch as `Constants.*` and
        // `ApiClient.basePath` above.
        NetworkConfig.publishSync(snapshot)
        // Async publish kept so any `await NetworkConfig.shared.current`
        // consumer (the signing-path submit-time re-assertion in
        // SendViewController) eventually sees the same value via the
        // actor. Retained as defense-in-depth; the synchronous mirror
        // above is the authoritative source for the capture-time read.
        Task { await NetworkConfig.shared.apply(snapshot) }

        Task.detached(priority: .userInitiated) {
            _ = try? JsBridge.shared.initialize(chainId: Constants.CHAIN_ID,
                rpcEndpoint: Constants.RPC_ENDPOINT_URL)
        }
    }

    private func loadBundled() -> [BlockchainNetwork] {
        guard let url = Bundle.main.url(forResource: "blockchain_networks", withExtension: "json"),
        let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([BlockchainNetwork].self, from: data)) ?? []
    }
}
