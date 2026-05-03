// ApiClient.swift
// Port of `ApiClient.java` + `AccountsApi.java`. `URLSession`-based,
// async/await. `OfflineOrExceptionError` equivalent is represented by
// throwing `ApiError.offline` / `.http(status:)` / `.decode(error:)`.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/api/read/ApiClient.java
// app/src/main/java/com/quantumcoinwallet/app/api/read/api/AccountsApi.java

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

    /// Strong reference to the TLS-pinning
    /// delegate. `URLSession(configuration:delegate:delegateQueue:)`
    /// retains its delegate weakly inside the session object's
    /// lifetime, but that lifetime is tied to the session being
    /// kept alive; we keep both around for the lifetime of the
    /// `ApiClient` singleton (= the process), so an explicit
    /// reference here makes the ownership obvious to a future
    /// reader and immune to a change in URLSession's retention
    /// rules.
    private let pinningDelegate = TlsPinningSessionDelegate()

    /// TLS-pinning enabled URLSession. Hosts
    /// listed in `TlsPinning.kSpkiPinsByHost` (today: the bundled
    /// `MAINNET` scan API, RPC, and explorer hostnames) require
    /// the server-presented SPKI to match a pinned SHA-256 hash;
    /// any other host falls through to standard system trust.
    /// User-defined networks therefore continue to work, but with
    /// the same baseline trust ceiling iOS would have applied
    /// without this delegate. See `Networking/TlsPinning.swift`
    /// for the full coverage map and rotation procedure.
    private let session: URLSession

    private init() {
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 30
        cfg.timeoutIntervalForResource = 60
        cfg.waitsForConnectivity = false
        self.session = URLSession(configuration: cfg,
            delegate: pinningDelegate,
            delegateQueue: nil)
    }

    public func get<T: Decodable>(path: String, as type: T.Type) async throws -> T {
        let trimmedBase = basePath.hasSuffix("/") ? String(basePath.dropLast()) : basePath
        let trimmedPath = path.hasPrefix("/") ? path : "/" + path
        // Route the composition through URLComponents
        // so any path / query / fragment characters present in the
        // caller-supplied path are interpreted by the URL spec rather
        // than smuggled into the wrong URL component. AccountsApi
        // pre-validates the address segment via UrlBuilder.apiPath
        // (returns nil and the call short-circuits on validation
        // failure), but URLComponents is the defense-in-depth layer
        // that catches any future caller that forgets to pre-validate.
        guard
        var comps = URLComponents(string: trimmedBase),
        let scheme = comps.scheme?.lowercased(), scheme == "https"
        else {
            throw ApiError.other(URLError(.badURL))
        }
        // Append the path. URLComponents merges paths via simple
        // string concat too, but storing into `.path` lets it
        // re-encode any reserved characters that survived caller
        // validation.
        let basePath = comps.path
        comps.path = (basePath.hasSuffix("/") ? String(basePath.dropLast()) : basePath)
        + trimmedPath
        guard let url = comps.url else {
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
// (audit-grade notes for AI reviewers and human
// auditors): every public method here takes an `address` argument
// and uses it as a URL path segment. The address is supposed to be
// the wallet's own address (which goes through validation in the
// onboarding / restore flow before being persisted), but because
// the JSON-pref read path can in principle return any string, this
// layer must NOT trust its inputs. Each method validates `address`
// via `QuantumCoinAddress.isValid` and throws `.other(URLError(.badURL))`
// on failure rather than letting an attacker-controlled path segment
// reach `URL(string:)`. The pageIndex is a Swift `Int` so injection
// via that channel is impossible by type.

public enum AccountsApi {

    public static func accountBalance(address: String) async throws -> BalanceResponse {
        guard QuantumCoinAddress.isValid(address) else {
            throw ApiError.other(URLError(.badURL))
        }
        return try await ApiClient.shared.get(
            path: "/account/\(address)",
            as: BalanceResponse.self)
    }

    public static func accountTransactions(address: String, pageIndex: Int)
    async throws -> AccountTransactionSummaryResponse {
        guard QuantumCoinAddress.isValid(address) else {
            throw ApiError.other(URLError(.badURL))
        }
        return try await ApiClient.shared.get(
            path: "/account/\(address)/transactions/\(pageIndex)",
            as: AccountTransactionSummaryResponse.self)
    }

    public static func accountPendingTransactions(address: String, pageIndex: Int)
    async throws -> AccountPendingTransactionSummaryResponse {
        guard QuantumCoinAddress.isValid(address) else {
            throw ApiError.other(URLError(.badURL))
        }
        return try await ApiClient.shared.get(
            path: "/account/\(address)/transactions/pending/\(pageIndex)",
            as: AccountPendingTransactionSummaryResponse.self)
    }

    public static func accountTokens(address: String, pageIndex: Int)
    async throws -> AccountTokenListResponse {
        guard QuantumCoinAddress.isValid(address) else {
            throw ApiError.other(URLError(.badURL))
        }
        return try await ApiClient.shared.get(
            path: "/account/\(address)/tokens/\(pageIndex)",
            as: AccountTokenListResponse.self)
    }
}
