// GasEstimator.swift
// RPC gas estimate through the bridge's txKind-dispatched
// `dexEstimateGas`, with the desktop buffer applied and the kind
// default as fallback on ANY failure (the caller never fails because
// an estimate failed). Android reference:
// app/src/main/java/com/quantumswap/app/gas/GasEstimator.java

import Foundation

@MainActor
public enum GasEstimator {

    public struct Result {
        public let gasLimit: Int64
        /// Bare number ("0.4762"), see GasFee.formatQ for display.
        public let feeNumber: String
        public let usedFallback: Bool
        public let error: String?
        /// Bridge echo on success: `router`, `factory`, `wq`.
        public let extra: [String: Any]

        public var feeLabel: String { feeNumber + " " + GasFee.feeUnit }
    }

    /// - parameter payload: kind-specific fields (fromTokenValue, amount,
    ///   tokenAddress ...) merged over the base chain payload.
    /// - parameter snapshot: optional open-time chain snapshot overlaid
    ///   last so a network switch mid-flow cannot re-target the estimate.
    public static func estimate(walletAddress: String, kind: GasKind,
                                payload: [String: Any], pairExists: Bool = true,
                                snapshot: [String: Any]? = nil) async -> Result {
        let fallback = kind.defaultFor(pairExists: pairExists)
        func fallbackResult(_ error: String?) -> Result {
            Result(gasLimit: fallback,
                   feeNumber: GasFee.feeNumberFor(gasLimit: fallback, address: walletAddress),
                   usedFallback: true, error: error, extra: [:])
        }
        let net = NetworkConfig.currentSync
        var p: [String: Any] = ["chainId": net.chainId, "rpcEndpoint": net.rpcEndpoint]
        for (k, v) in payload { p[k] = v }
        if let snapshot { for (k, v) in snapshot { p[k] = v } }
        p["txKind"] = kind.txKind
        p["fromAddress"] = walletAddress
        p["bufferPercent"] = kind.bufferPercent
        do {
            let json = try await JsBridge.shared.estimateGasAsync(payload: p)
            let data = try GasEstimator.unwrapData(json)
            guard let raw = GasEstimator.int64(data["gasLimit"]), raw > 0 else {
                return fallbackResult("zero estimate")
            }
            let buffered = kind.applyBuffer(raw)
            return Result(gasLimit: buffered,
                          feeNumber: GasFee.feeNumberFor(gasLimit: buffered, address: walletAddress),
                          usedFallback: false, error: nil, extra: data)
        } catch {
            return fallbackResult(String(error.localizedDescription.prefix(300)))
        }
    }

    /// Unwrap `{ success, data }` from a bridge response.
    static func unwrapData(_ json: String) throws -> [String: Any] {
        guard let data = json.data(using: .utf8),
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let inner = obj["data"] as? [String: Any] else {
            throw JsEngineError.callFailed("estimateGas response missing data")
        }
        return inner
    }

    static func int64(_ raw: Any?) -> Int64? {
        if let s = raw as? String { return Int64(s.trimmingCharacters(in: .whitespaces)) }
        if let n = raw as? Int64 { return n }
        if let n = raw as? Int { return Int64(n) }
        if let n = raw as? NSNumber { return n.int64Value }
        return nil
    }

    /// Desktop resolveGasForTx: a positive state limit (estimate OR
    /// manual override) wins; otherwise the kind default.
    public static func resolve(state: GasState, kind: GasKind, pairExists: Bool,
                               walletAddress: String) -> (gasLimit: Int64, feeNumber: String) {
        if let limit = state.gasLimit, limit > 0 {
            let fee = state.gasFeeNumber ?? GasFee.feeNumberFor(gasLimit: limit, address: walletAddress)
            return (limit, fee)
        }
        let d = kind.defaultFor(pairExists: pairExists)
        return (d, GasFee.feeNumberFor(gasLimit: d, address: walletAddress))
    }
}
