//
// ApiClient.swift
//
// Port of `ApiClient.java` + `AccountsApi.java`. `URLSession`-based,
// async/await. `OfflineOrExceptionError` equivalent is represented by
// throwing `ApiError.offline` / `.http(status:)` / `.decode(error:)`.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/api/read/ApiClient.java
//   app/src/main/java/com/quantumcoinwallet/app/api/read/api/AccountsApi.java
//

import Foundation

public enum ApiError: Error {
    case offline
    case http(status: Int, body: String?)
    case decode(Error)
    case other(Error)
}

public final class ApiClient: @unchecked Sendable {

    public static let shared = ApiClient()

    /// Current scan API base URL. Updated by `BlockchainNetworkManager`.
    public var basePath: String = ""

    private let session: URLSession = {
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest  = 30
        cfg.timeoutIntervalForResource = 60
        cfg.waitsForConnectivity = false
        return URLSession(configuration: cfg)
    }()

    private init() {}

    public func get<T: Decodable>(path: String, as type: T.Type) async throws -> T {
        let trimmedBase = basePath.hasSuffix("/") ? String(basePath.dropLast()) : basePath
        let trimmedPath = path.hasPrefix("/") ? path : "/" + path
        guard let url = URL(string: trimmedBase + trimmedPath) else {
            throw ApiError.other(URLError(.badURL))
        }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse else {
                throw ApiError.other(URLError(.badServerResponse))
            }
            guard (200..<300).contains(http.statusCode) else {
                throw ApiError.http(status: http.statusCode,
                                    body: String(data: data, encoding: .utf8))
            }
            do {
                return try JSONDecoder().decode(T.self, from: data)
            } catch {
                throw ApiError.decode(error)
            }
        } catch let urlError as URLError where Self.isOffline(urlError) {
            throw ApiError.offline
        } catch let apiError as ApiError {
            throw apiError
        } catch {
            throw ApiError.other(error)
        }
    }

    private static func isOffline(_ e: URLError) -> Bool {
        switch e.code {
        case .notConnectedToInternet, .networkConnectionLost,
             .cannotFindHost, .cannotConnectToHost, .timedOut,
             .dataNotAllowed: return true
        default: return false
        }
    }
}

// MARK: - AccountsApi

public enum AccountsApi {

    public static func accountBalance(address: String) async throws -> BalanceResponse {
        try await ApiClient.shared.get(path: "/account/\(address)", as: BalanceResponse.self)
    }

    public static func accountTransactions(address: String, pageIndex: Int)
      async throws -> AccountTransactionSummaryResponse {
        try await ApiClient.shared.get(path: "/account/\(address)/transactions/\(pageIndex)",
                                       as: AccountTransactionSummaryResponse.self)
    }

    public static func accountPendingTransactions(address: String, pageIndex: Int)
      async throws -> AccountPendingTransactionSummaryResponse {
        try await ApiClient.shared.get(path: "/account/\(address)/transactions/pending/\(pageIndex)",
                                       as: AccountPendingTransactionSummaryResponse.self)
    }

    public static func accountTokens(address: String, pageIndex: Int)
      async throws -> AccountTokenListResponse {
        try await ApiClient.shared.get(path: "/account/\(address)/tokens/\(pageIndex)",
                                       as: AccountTokenListResponse.self)
    }
}
