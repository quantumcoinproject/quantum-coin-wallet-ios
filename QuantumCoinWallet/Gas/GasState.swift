// GasState.swift
// Per-chip gas state: last estimate or manual override + a staleness
// token so a late estimate can never clobber the user's edit.
// Android reference: app/src/main/java/com/quantumswap/app/gas/GasState.java

import Foundation

public final class GasState {
    public var gasLimit: Int64?
    /// Bare number string ("0.4762"), never with the unit.
    public var gasFeeNumber: String?
    public var overridden = false
    public private(set) var token = 0

    public init() { }

    public func reset() {
        gasLimit = nil
        gasFeeNumber = nil
        overridden = false
        token += 1
    }

    @discardableResult
    public func invalidate() -> Int {
        token += 1
        return token
    }

    public var isReady: Bool {
        overridden || (gasLimit != nil && gasFeeNumber != nil)
    }
}
