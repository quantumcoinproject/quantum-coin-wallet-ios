//
// Constants.swift
//
// Port of the static fields on `GlobalMethods.java` that are used by UI
// code. Kept in a narrowly-scoped enum so the auto-completion hits are
// obvious at call sites.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/utils/GlobalMethods.java
//

import Foundation

public enum Constants {

    // MARK: - Block explorer URL templates

    public static let BLOCK_EXPLORER_TX_HASH_URL           = "/txn/{txhash}"
    public static let BLOCK_EXPLORER_ACCOUNT_TRANSACTION_URL = "/account/{address}/txn/page"

    // MARK: - External links

    public static let DP_DOCS_URL = "https://quantumcoin.org/"

    // MARK: - Security / UX

    public static let MINIMUM_PASSWORD_LENGTH: Int = 12
    public static let UNLOCK_TIMEOUT_MS: Int      = 300_000 // 5 minutes

    // MARK: - Wallet types / seed-length buckets

    /// keyType 3 = default (32 seed words).
    public static let KEY_TYPE_DEFAULT: Int  = 3
    /// keyType 5 = advanced (36 seed words).
    public static let KEY_TYPE_ADVANCED: Int = 5

    // MARK: - Network / active-session mutable state

    /// Updated by `BlockchainNetworkManager.setActive(...)` after a
    /// network switch so every screen sees the same base URL.
    public nonisolated(unsafe) static var SCAN_API_URL: String = ""
    public nonisolated(unsafe) static var RPC_ENDPOINT_URL: String = ""
    public nonisolated(unsafe) static var BLOCK_EXPLORER_URL: String = ""
    public nonisolated(unsafe) static var CHAIN_ID: Int = 0
}
