//
// ApiModels.swift
//
// Swift `Codable` models that parse the REST responses from the
// blockchain scan API. Preserves the two Android serialization quirks
// called out in `ios_clone_spec` §5.2:
//
//  - `items` vs `getResult()` discrepancy on transaction responses.
//  - `_Balance` field backed by JSON key `balance`.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/api/read/model/*.java
//

import Foundation

public enum TransactionType: String, Codable {
    case coinTransfer    = "CoinTransfer"
    case newToken        = "NewToken"
    case tokenTransfer   = "TokenTransfer"
    case newSmartContract = "NewSmartContract"
    case smartContract   = "SmartContract"
}

public struct Balance: Codable {
    public let balance: String
    private enum CodingKeys: String, CodingKey { case balance }
}

public struct BalanceResponse: Codable {
    public let result: Balance?
    public let error: ErrorResponseModel?
}

public struct ErrorResponseModel: Codable {
    public let errorMessage: String?
    public let details: String?
}

public struct Receipt: Codable {
    public let status: String?
}

public struct AccountTransaction: Codable {
    public let hash: String?
    public let from: String?
    public let to: String?
    public let value: String?
    public let type: TransactionType?
    public let date: String?
    public let blockNumber: String?
    public let nonce: String?
    public let gasUsed: String?
    public let gasPrice: String?
    public let status: String?
    public let receipt: Receipt?
    public let contract: String?
    public let tokenAmount: String?
    public let tokenSymbol: String?
}

public struct AccountTransactionSummaryResponse: Codable {
    public let result: [AccountTransaction]?
    public let error: ErrorResponseModel?
    public let totalPages: Int?
    public let pageIndex: Int?

    private enum CodingKeys: String, CodingKey {
        case result     = "items"
        case error
        case totalPages
        case pageIndex
    }
}

public struct AccountPendingTransactionSummaryResponse: Codable {
    public let result: [AccountTransaction]?
    public let error: ErrorResponseModel?
    public let totalPages: Int?
    public let pageIndex: Int?

    private enum CodingKeys: String, CodingKey {
        case result = "items"
        case error
        case totalPages
        case pageIndex
    }
}

public struct AccountTokenSummary: Codable {
    public let contractAddress: String?
    public let name: String?
    public let symbol: String?
    public let balance: String?
    public let decimals: Int?
}

public struct AccountTokenListResponse: Codable {
    public let result: [AccountTokenSummary]?
    public let error: ErrorResponseModel?
    public let totalPages: Int?
    public let pageIndex: Int?

    private enum CodingKeys: String, CodingKey {
        case result     = "items"
        case error
        case totalPages
        case pageIndex
    }
}
