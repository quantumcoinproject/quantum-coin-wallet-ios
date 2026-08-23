// GasKind.swift
// Per-transaction-kind gas defaults and estimate buffers (desktop
// src/app/gas.ts / gas-fee-core.ts). Android reference:
// app/src/main/java/com/quantumswap/app/gas/GasKind.java

import Foundation

public enum GasKind: String, CaseIterable {
    case sendCoin
    case sendToken
    case approve
    case approveToken
    case swap
    case addLiquidity
    case removeLiquidity
    case createPair
    case deployToken

    /// `txKind` value understood by the bridge `dexEstimateGas` handler.
    public var txKind: String { rawValue }

    /// Desktop per-kind default gas limit (used when the RPC estimate
    /// fails or returns 0).
    public var defaultGas: Int64 {
        switch self {
        case .sendCoin: return 21_000
        case .sendToken: return 84_000
        case .approve: return 84_000
        case .approveToken: return 84_000
        case .swap: return 200_000
        case .addLiquidity: return 600_000
        case .removeLiquidity: return 600_000
        case .createPair: return 4_500_000
        case .deployToken: return 6_000_000
        }
    }

    /// Desktop GAS_ESTIMATE_BUFFER_PERCENT = 10 for everything except
    /// a plain coin send (GAS_NO_BUFFER_PERCENT).
    public var bufferPercent: Int64 {
        self == .sendCoin ? 0 : 10
    }

    /// Adding liquidity to a pair that does not exist yet also deploys
    /// the pair contract.
    public static let addLiquidityNewPairDefault: Int64 = 4_500_000

    public func defaultFor(pairExists: Bool) -> Int64 {
        if self == .addLiquidity && !pairExists { return GasKind.addLiquidityNewPairDefault }
        return defaultGas
    }

    /// Desktop applyGasBuffer: floor(raw * (100 + pct) / 100).
    public func applyBuffer(_ raw: Int64) -> Int64 {
        (raw * (100 + bufferPercent)) / 100
    }
}
