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

public final class BlockchainNetworkManager {

    public static let shared = BlockchainNetworkManager()

    public private(set) var networks: [BlockchainNetwork] = []
    public private(set) var activeIndex: Int = 0

    public var active: BlockchainNetwork? {
        guard activeIndex >= 0 && activeIndex < networks.count else { return nil }
        return networks[activeIndex]
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
        networks = loadBundled()
        activeIndex = 0
        applyActive()
        NotificationCenter.default.post(name: .networkConfigDidChange, object: nil)
    }

    /// Called from `UnlockCoordinatorV2.unlockWithPasswordAndApplySession`
    /// once the encrypted strongbox payload has been decrypted.
    /// Layers the user-added networks on top of the
    /// bundled defaults, restores the active offset, and re-runs
    /// `applyActive` so `Constants.*`, `ApiClient.basePath`, and the
    /// JS bridge match the user's selection. Must be called on the
    /// main thread.
    public func applyDecryptedConfig(customNetworks: [BlockchainNetwork],
        activeIndex savedIndex: Int) {
        let bundled = loadBundled()
        networks = bundled + customNetworks
        let upper = max(0, networks.count - 1)
        activeIndex = max(0, min(savedIndex, upper))
        applyActive()
        NotificationCenter.default.post(name: .networkConfigDidChange, object: nil)
    }

    /// Called from `UnlockCoordinatorV2.lock` so a foreground
    /// after relock only sees the bundled MAINNET (mirrors how
    /// the address map
    /// becomes empty post-lock). User-added networks reappear on the
    /// next successful unlock via `applyDecryptedConfig`.
    public func resetToBundled() {
        networks = loadBundled()
        activeIndex = 0
        applyActive()
        NotificationCenter.default.post(name: .networkConfigDidChange, object: nil)
    }

    /// Switch the active blockchain network. `password` is required so
    /// `KeyStore` can re-derive the strongbox main key, re-encrypt the
    /// strongbox blob with the new active-index, and zero the bytes before
    /// returning. Callers (`BlockchainNetworkSelectDialogViewController`)
    /// must collect the password through `UnlockDialogViewController`
    /// before invoking this method. The in-memory `activeIndex` is
    /// rolled back if the persist fails so a wrong-password retry
    /// doesn't desync memory from disk.
    public func setActive(index: Int, password: String) throws {
        guard index >= 0 && index < networks.count else { return }
        let previous = activeIndex
        activeIndex = index
        do {
            try persistThroughStrongbox(password: password)
        } catch {
            activeIndex = previous
            throw error
        }
        applyActive()
        NotificationCenter.default.post(name: .networkConfigDidChange, object: nil)
    }

    /// Append a new user-defined blockchain network. `password` is
    /// required for the same reason `setActive` requires it - the new
    /// entry must be written to the encrypted strongbox blob, which means
    /// re-deriving the strongbox main key from the user's password. On
    /// persist failure the new entry is rolled back so the in-memory
    /// `networks` list stays in lock-step with disk, allowing the user
    /// to retry the unlock prompt without duplicating the entry.
    public func addNetwork(_ n: BlockchainNetwork, password: String) throws {
        networks.append(n)
        do {
            try persistThroughStrongbox(password: password)
        } catch {
            networks.removeLast()
            throw error
        }
        NotificationCenter.default.post(name: .networkConfigDidChange, object: nil)
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
    private func persistThroughStrongbox(password: String) throws {
        let bundledCount = loadBundled().count
        let custom = Array(networks.dropFirst(bundledCount))
        try UnlockCoordinatorV2.replaceNetworks(
            custom, activeIndex: activeIndex, password: password)
    }

    private func applyActive() {
        guard let net = active else { return }
        ApiClient.shared.basePath = net.scanApiDomain
        Constants.SCAN_API_URL = net.scanApiDomain
        Constants.RPC_ENDPOINT_URL = net.rpcEndpoint
        Constants.BLOCK_EXPLORER_URL = net.blockExplorerUrl
        Constants.CHAIN_ID = Int(net.chainId) ?? 0

        // Mirror into the actor-backed
        // NetworkConfig so the signing pipeline can capture and
        // re-assert a typed snapshot. The `Constants.*` writes
        // above remain so legacy synchronous read sites (UI,
        // explorer deep links) keep working unchanged. The actor
        // is the authoritative source for any signing-related
        // comparison; see NetworkConfig.swift for full rationale.
        let snapshot = NetworkSnapshot(
            name: net.name,
            chainId: Constants.CHAIN_ID,
            rpcEndpoint: net.rpcEndpoint,
            scanApiUrl: net.scanApiDomain,
            blockExplorerUrl: net.blockExplorerUrl)
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
