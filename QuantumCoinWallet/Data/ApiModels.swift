// ApiModels.swift
// Swift `Codable` models that parse the REST responses from the
// blockchain scan API. Preserves the two Android serialization quirks
// called out in `ios_clone_spec` §5.2:
// - `items` vs `getResult` discrepancy on transaction responses.
// - `_Balance` field backed by JSON key `balance`.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/api/read/model/*.java

import Foundation

public enum TransactionType: String, Codable {
    case coinTransfer = "CoinTransfer"
    case newToken = "NewToken"
    case tokenTransfer = "TokenTransfer"
    case newSmartContract = "NewSmartContract"
    case smartContract = "SmartContract"
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

    /// JSON key mapping mirrors Android `AccountTransactionSummary.java`:
    /// - `date` <- `createdAt` (Android `SERIALIZED_NAME_CREATED_AT`)
    /// - `type` <- `transactionType` (Android
    /// `SERIALIZED_NAME_TRANSACTION_TYPE`)
    /// Without these aliases the date column rendered empty and the
    /// transaction type was always nil because the scan API never
    /// emits literal `"date"` / `"type"` keys.
    private enum CodingKeys: String, CodingKey {
        case hash, from, to, value
        case type = "transactionType"
        case date = "createdAt"
        case blockNumber, nonce, gasUsed, gasPrice
        case status, receipt, contract, tokenAmount, tokenSymbol
    }

    /// Custom decoder mirrors the Android `AccountTransactionSummary`
    /// model where fields like `blockNumber`, `nonce`, `gasUsed`,
    /// `gasPrice`, `value`, and `tokenAmount` are typed loosely
    /// (`Object` / `Double`) and accept either a JSON number or a
    /// JSON string from the scan API. The strict synthesised
    /// `Decodable` would otherwise crash with
    /// `Expected to decode String but found number` the moment the
    /// server emits e.g. `"blockNumber": 12345` as a literal number.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        hash = try c.decodeIfPresent(String.self, forKey: .hash)
        from = try c.decodeIfPresent(String.self, forKey: .from)
        to = try c.decodeIfPresent(String.self, forKey: .to)
        type = try c.decodeIfPresent(TransactionType.self, forKey: .type)
        date = try c.decodeIfPresent(String.self, forKey: .date)
        status = try c.decodeIfPresent(String.self, forKey: .status)
        receipt = try c.decodeIfPresent(Receipt.self, forKey: .receipt)
        contract = try c.decodeIfPresent(String.self, forKey: .contract)
        tokenSymbol = try c.decodeIfPresent(String.self, forKey: .tokenSymbol)

        value = try c.decodeStringOrNumberIfPresent(forKey: .value)
        blockNumber = try c.decodeStringOrNumberIfPresent(forKey: .blockNumber)
        nonce = try c.decodeStringOrNumberIfPresent(forKey: .nonce)
        gasUsed = try c.decodeStringOrNumberIfPresent(forKey: .gasUsed)
        gasPrice = try c.decodeStringOrNumberIfPresent(forKey: .gasPrice)
        tokenAmount = try c.decodeStringOrNumberIfPresent(forKey: .tokenAmount)
    }
}

extension KeyedDecodingContainer {
    /// Decode a JSON value that may be either a string or a number
    /// into a Swift `String?`. JSON `null` and missing keys both
    /// return `nil`. Used for fields the scan API types loosely
    /// across endpoints (e.g. `blockNumber` arrives as a JSON number
    /// on the transactions list but as a 0x-hex string elsewhere).
    func decodeStringOrNumberIfPresent(forKey key: Key) throws -> String? {
        guard contains(key) else { return nil }
        if (try? decodeNil(forKey: key)) == true { return nil }
        if let s = try? decode(String.self, forKey: key) { return s }
        if let i = try? decode(Int64.self, forKey: key) { return String(i) }
        if let u = try? decode(UInt64.self, forKey: key) { return String(u) }
        if let d = try? decode(Double.self, forKey: key) {
            // Whole-number doubles round-trip as `1234` rather than
            // `1234.0` so downstream string comparisons / hex
            // conversions behave like their Android counterparts.
            if d.isFinite && d == d.rounded() && abs(d) < 1e18 {
                return String(Int64(d))
            }
            return String(d)
        }
        return nil
    }
}

public struct AccountTransactionSummaryResponse: Codable {
    public let result: [AccountTransaction]?
    public let error: ErrorResponseModel?
    public let totalPages: Int?
    public let pageIndex: Int?

    /// The scan API returns the page total under JSON key
    /// `pageCount` (Android `AccountTransactionSummaryResponse.java`,
    /// `SERIALIZED_NAME_PAGE_COUNT = "pageCount"`). The Swift property
    /// name `totalPages` is preserved so the existing pagination
    /// callers in `AccountTransactionsViewController` keep compiling.
    /// Without this alias the field always decoded as nil, leaving
    /// `pageCount` at 0 in the controller and breaking prev/next.
    private enum CodingKeys: String, CodingKey {
        case result = "items"
        case error
        case totalPages = "pageCount"
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
        case totalPages = "pageCount"
        case pageIndex
    }
}

public struct AccountTokenSummary: Codable {
    public let contractAddress: String?
    public let name: String?
    public let symbol: String?
    public let balance: String?
    public let decimals: Int?

    /// The scan API returns the token balance under JSON key
    /// `tokenBalance` (Android model `AccountTokenSummary.java`,
    /// `SERIALIZED_NAME_TOKEN_BALANCE = "tokenBalance"`). The Swift
    /// property stays `balance` so call sites read intuitively.
    private enum CodingKeys: String, CodingKey {
        case contractAddress
        case name
        case symbol
        case balance = "tokenBalance"
        case decimals
    }
}

public struct AccountTokenListResponse: Codable {
    public let result: [AccountTokenSummary]?
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
