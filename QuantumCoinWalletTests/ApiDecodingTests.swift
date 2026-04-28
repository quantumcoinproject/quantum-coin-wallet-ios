//
// ApiDecodingTests.swift
//
// Golden-file tests for the REST decoders. Each test decodes a
// captured-from-live-API JSON fixture and checks the preserved Android
// quirks: `items` vs `result` and `_Balance` vs `balance`.
//
// Place fixtures under `QuantumCoinWalletTests/Fixtures/`.
//

import XCTest
@testable import QuantumCoinWallet

final class ApiDecodingTests: XCTestCase {

    func testAccountTransactionsDecodesItemsKey() throws {
        let data = try loadFixture("account_transactions.json")
        let resp = try JSONDecoder().decode(AccountTransactionSummaryResponse.self, from: data)
        XCTAssertNotNil(resp.result)
    }

    func testPendingTransactionsDecodesItemsKey() throws {
        let data = try loadFixture("account_pending_transactions.json")
        let resp = try JSONDecoder().decode(AccountPendingTransactionSummaryResponse.self, from: data)
        XCTAssertNotNil(resp.result)
    }

    func testAccountBalanceDecodesBalanceKey() throws {
        let data = try loadFixture("account_balance.json")
        let resp = try JSONDecoder().decode(BalanceResponse.self, from: data)
        XCTAssertNotNil(resp.result?.balance)
    }

    func testAccountTokensDecodes() throws {
        let data = try loadFixture("account_tokens.json")
        let resp = try JSONDecoder().decode(AccountTokenListResponse.self, from: data)
        XCTAssertNotNil(resp.result)
    }

    private func loadFixture(_ name: String) throws -> Data {
        guard let url = Bundle(for: type(of: self))
                .url(forResource: (name as NSString).deletingPathExtension,
                     withExtension: (name as NSString).pathExtension)
        else {
            throw XCTSkip("Fixture \(name) not installed")
        }
        return try Data(contentsOf: url)
    }
}
