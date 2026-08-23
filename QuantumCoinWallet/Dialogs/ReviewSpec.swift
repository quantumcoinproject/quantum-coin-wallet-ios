// ReviewSpec.swift
// Data model for the transaction-review dialog rows (desktop
// #modalTransactionReview / buildStepReview). Optional rows are hidden
// when nil; `HIDE` lets a per-step override clear a base-spec row.
// Android reference: TransactionReviewDialog.ReviewSpec

import Foundation

public struct ReviewSpec {

    /// Sentinel an override can use to HIDE a row the base spec set.
    public static let HIDE = " HIDE"

    public var action: String?
    public var actionLabelKey: String?
    public var contractAddress: String?
    /// Contract-address row links to /token/ (ERC20 / LP token) instead
    /// of /account/ (router / factory).
    public var contractIsToken = false
    public var fromTokenContract: String?
    public var fromTokenContractLabelKey: String?
    public var toTokenContract: String?
    public var fromAddress: String?
    public var toAddress: String?
    public var quantityLabelKey: String?
    public var quantityValue: String?
    public var tokenQuantityLabelKey: String?
    public var tokenQuantityValue: String?
    public var gasLimit: Int64?
    public var gasFeeLabel: String?
    public var networkText: String?

    public init() { }

    // Builder-style setters (keep call sites close to the Android/desktop specs).
    public func action(_ v: String?) -> ReviewSpec { var c = self; c.action = v; return c }
    public func actionLabelKey(_ v: String?) -> ReviewSpec { var c = self; c.actionLabelKey = v; return c }
    public func contractAddress(_ v: String?) -> ReviewSpec { var c = self; c.contractAddress = v; return c }
    public func contractIsToken(_ v: Bool) -> ReviewSpec { var c = self; c.contractIsToken = v; return c }
    public func fromTokenContract(_ v: String?) -> ReviewSpec { var c = self; c.fromTokenContract = v; return c }
    public func fromTokenContractLabelKey(_ v: String?) -> ReviewSpec { var c = self; c.fromTokenContractLabelKey = v; return c }
    public func toTokenContract(_ v: String?) -> ReviewSpec { var c = self; c.toTokenContract = v; return c }
    public func fromAddress(_ v: String?) -> ReviewSpec { var c = self; c.fromAddress = v; return c }
    public func toAddress(_ v: String?) -> ReviewSpec { var c = self; c.toAddress = v; return c }
    public func quantityLabelKey(_ v: String?) -> ReviewSpec { var c = self; c.quantityLabelKey = v; return c }
    public func quantityValue(_ v: String?) -> ReviewSpec { var c = self; c.quantityValue = v; return c }
    public func tokenQuantityLabelKey(_ v: String?) -> ReviewSpec { var c = self; c.tokenQuantityLabelKey = v; return c }
    public func tokenQuantityValue(_ v: String?) -> ReviewSpec { var c = self; c.tokenQuantityValue = v; return c }
    public func networkText(_ v: String?) -> ReviewSpec { var c = self; c.networkText = v; return c }

    public func gas(_ limit: Int64, _ feeLabel: String) -> ReviewSpec {
        var c = self
        c.gasLimit = limit
        c.gasFeeLabel = feeLabel
        return c
    }

    /// Desktop buildStepReview: override values win key-by-key;
    /// `HIDE` clears a base value.
    public func mergeOver(_ o: ReviewSpec?) -> ReviewSpec {
        guard let o else { return self }
        var m = self
        m.action = pick(o.action, m.action)
        m.actionLabelKey = pick(o.actionLabelKey, m.actionLabelKey)
        m.contractAddress = pick(o.contractAddress, m.contractAddress)
        if o.contractAddress != nil { m.contractIsToken = o.contractIsToken }
        m.fromTokenContract = pick(o.fromTokenContract, m.fromTokenContract)
        m.fromTokenContractLabelKey = pick(o.fromTokenContractLabelKey, m.fromTokenContractLabelKey)
        m.toTokenContract = pick(o.toTokenContract, m.toTokenContract)
        m.fromAddress = pick(o.fromAddress, m.fromAddress)
        m.toAddress = pick(o.toAddress, m.toAddress)
        m.quantityLabelKey = pick(o.quantityLabelKey, m.quantityLabelKey)
        m.quantityValue = pick(o.quantityValue, m.quantityValue)
        m.tokenQuantityLabelKey = pick(o.tokenQuantityLabelKey, m.tokenQuantityLabelKey)
        m.tokenQuantityValue = pick(o.tokenQuantityValue, m.tokenQuantityValue)
        if let g = o.gasLimit { m.gasLimit = g }
        m.gasFeeLabel = pick(o.gasFeeLabel, m.gasFeeLabel)
        m.networkText = pick(o.networkText, m.networkText)
        return m
    }

    private func pick(_ override: String?, _ base: String?) -> String? {
        guard let override else { return base }
        return override == ReviewSpec.HIDE ? nil : override
    }

    /// "<name> (chain <id>)", or "(chain <id>)" when the name is empty.
    public static func networkText() -> String {
        let snap = NetworkConfig.currentSync
        let suffix = Localization.shared.lang("chain-id-suffix", fallback: "chain")
        let name = snap.name.trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? "(\(suffix) \(snap.chainId))" : "\(name) (\(suffix) \(snap.chainId))"
    }
}
