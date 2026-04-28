//
// AccountTransactionUi.swift
//
// Port of `AccountTransactionUi.java`. Holds display rules for the
// transaction list that must be shared between the adapter row layout
// and the explorer-open click guards.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/utils/AccountTransactionUi.java
//

import Foundation

public enum AccountTransactionUi {

    /// Null/empty-safe conversion for a transaction address or hash.
    /// Callers should use this for `to`, `from`, and `hash`: the `to`
    /// field in particular is nullable on-chain (contract-creation
    /// transactions) and can also arrive as whitespace after
    /// serialization, which would otherwise break downstream URL
    /// formatting and click guards.
    public static func safeAddress(_ raw: Any?) -> String {
        guard let raw = raw else { return "" }
        let s: String
        switch raw {
        case let str as String:    s = str
        case let ns as NSString:   s = ns as String
        default:                    s = String(describing: raw)
        }
        return s.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Mirrors desktop: `txn.status !== null && txn.status == "0x1"`.
    /// Used by the transaction adapter to decide success vs. failure
    /// icon on the Completed tab.
    public static func isCompletedSuccessful(status: Any?, receiptStatus: Any?) -> Bool {
        if let st = status, !isNull(st) {
            return compareStatus(st)
        }
        if let rs = receiptStatus {
            return compareStatus(rs)
        }
        return false
    }

    private static func compareStatus(_ raw: Any) -> Bool {
        let s = safeAddress(raw).lowercased()
        return s == "0x1"
    }

    private static func isNull(_ v: Any) -> Bool {
        if v is NSNull { return true }
        if let s = v as? String { return s.isEmpty }
        return false
    }
}
