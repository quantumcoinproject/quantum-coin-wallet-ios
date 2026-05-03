// NetworkConfig.swift (Networking layer)
// Actor-backed network configuration with
// a value-type `NetworkSnapshot` that signing call sites capture at
// "Review" time and re-assert against at "Submit" time.
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// The legacy state lived in `Constants.SCAN_API_URL`,
// `Constants.RPC_ENDPOINT_URL`, `Constants.BLOCK_EXPLORER_URL`,
// and `Constants.CHAIN_ID` - all declared as
// `nonisolated(unsafe) static var`. Three race-class problems:
// 1. **Signing-path race.** `SendViewController.presentUnlockAndSend`
// captures the active chain-id at the moment the user taps
// "Review", but the bridge call that signs the transaction
// re-reads `Constants.CHAIN_ID` and `Constants.RPC_ENDPOINT_URL`
// at submit time. If the user (or a detached
// `BlockchainNetworkManager.applyActive` task) toggles
// networks between review and submit, the signed transaction
// gets bound to a different chain-id than the user
// confirmed - producing a mis-bound EIP-155 signature that
// replays on the wrong chain.
// 2. **Concurrent-init race.** `applyActive` schedules a detached
// `JsBridge.initialize(...)` task. If the user then triggers
// another network switch before that task completes, the two
// initialise calls can interleave and leave the bridge in
// a hybrid state (RPC pointing one place, chain-id pointing
// another).
// 3. **Reader-of-stale-constants race.** Any UI surface that
// displays the network name, address-strip explorer button,
// token-row contract link, etc. reads from Constants. With
// no synchronisation, the read can tear (Swift's String is
// not atomic on assignment).
// The fix is to introduce an actor whose `current` is the source
// of truth, and have signing call sites capture an immutable
// `NetworkSnapshot` value at the moment of user intent. The
// actor's `apply(_:)` is the only mutation entry point. The
// legacy `Constants.*` mirrors are kept in sync from the actor
// so non-signing read sites (UI display, deep links) continue
// to work unchanged - they accept the existing tearing risk for
// a cosmetic value, while the signing path has a correctness-
// critical guarantee via the captured snapshot.
// Tradeoffs:
// - Actors require async access. The signing pipeline is already
// a `Task.detached`, so this is a natural fit. Synchronous read
// sites continue to read `Constants.*` mirrors; we accept the
// cosmetic-only tearing risk on those because the failure mode
// is "address strip briefly shows the old network name" rather
// than "signed a tx with the wrong chain-id".
// - The post-submit assertion catches the cross-flight
// toggle case where the user (or a programmatic switch)
// changed networks between Review and Submit. The actor's
// value-type snapshot makes the comparison cheap and total
// (`Equatable`).
// - layers on TOP of this: the same captured snapshot is
// forwarded to the bridge call and re-asserted at submit time
// against (a) the actor's current state and (b) the wallet's
// current address-for-index binding, so a wallet-switch-mid-
// flight (e.g. user backgrounded the app, switched wallets,
// foregrounded) ALSO aborts with an explicit error.

import Foundation

/// Immutable snapshot of the network configuration at a single
/// moment in time. The value type makes captures cheap and
/// comparisons total. Signing call sites capture one of these at
/// "Review" tap and re-assert against the actor's current value at
/// "Submit" time.
public struct NetworkSnapshot: Equatable, Sendable {
    public let name: String
    public let chainId: Int
    public let rpcEndpoint: String
    public let scanApiUrl: String
    public let blockExplorerUrl: String

    public init(name: String,
        chainId: Int,
        rpcEndpoint: String,
        scanApiUrl: String,
        blockExplorerUrl: String) {
        self.name = name
        self.chainId = chainId
        self.rpcEndpoint = rpcEndpoint
        self.scanApiUrl = scanApiUrl
        self.blockExplorerUrl = blockExplorerUrl
    }

    /// `true` if `name`, `chainId`, `rpcEndpoint`, `scanApiUrl`,
    /// and `blockExplorerUrl` ALL match. Used by the signing pipe
    /// to detect mid-flight network toggles. The compiler-derived
    /// `Equatable` is sufficient.
    public static let empty = NetworkSnapshot(
        name: "", chainId: 0, rpcEndpoint: "",
        scanApiUrl: "", blockExplorerUrl: "")
}

public actor NetworkConfig {

    public static let shared = NetworkConfig()

    private var snapshot: NetworkSnapshot = .empty

    private init() {}

    /// Read the current snapshot. Signing call sites use this at
    /// "Review" tap to capture the user's intended chain.
    public var current: NetworkSnapshot { snapshot }

    /// Replace the canonical snapshot. Called only from
    /// `BlockchainNetworkManager.applyActive` whenever the user
    /// switches networks, the strongbox unlocks (and custom networks
    /// activate), or a fresh launch initialises the bundled
    /// default. The `Constants.*` mirrors are updated by the
    /// caller for legacy sync read sites; this actor is the
    /// authoritative source for any signing-related comparison.
    public func apply(_ next: NetworkSnapshot) {
        snapshot = next
    }
}

/// Errors returned by signing call sites that capture a
/// `NetworkSnapshot` and re-assert it before submit.
public enum NetworkAssertionError: Error, CustomStringConvertible {
    /// The active network changed between "Review" and "Submit".
    /// Signing must abort and require the user to re-confirm so a
    /// chain-id-bound signature cannot leak across networks.
    case networkSwitchedMidFlight(captured: NetworkSnapshot,
        current: NetworkSnapshot)
    /// The wallet's "current" wallet index now points at a
    /// different address than the one the user confirmed in the
    /// review dialog. .
    case walletSwitchedMidFlight(capturedAddress: String,
        currentAddress: String)

    public var description: String {
        switch self {
            case .networkSwitchedMidFlight(let cap, let cur):
            return "Network changed during transaction "
            + "(was \(cap.name)/\(cap.chainId), now \(cur.name)/\(cur.chainId)). "
            + "Please review and resubmit."
            case .walletSwitchedMidFlight(let cap, let cur):
            return "Active wallet changed during transaction "
            + "(was \(cap), now \(cur)). Please review and resubmit."
        }
    }
}
