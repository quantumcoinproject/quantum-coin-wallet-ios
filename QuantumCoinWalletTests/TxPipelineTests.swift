// TxPipelineTests.swift
// ReviewSpec merge rules, TxStatusPoller status mapping, explorer
// token-URL composition and the DEX allowlist.

import XCTest
@testable import QuantumCoinWallet

final class ReviewSpecTests: XCTestCase {

    func testMergeOverOverrideWinsAndHideClears() {
        let base = ReviewSpec()
            .action("Swap A for B")
            .fromTokenContract("0xaa")
            .toTokenContract("0xbb")
            .toAddress("0xrouter")
            .quantityValue("10")
        let override = ReviewSpec()
            .action("Approve A")
            .toTokenContract(ReviewSpec.HIDE)
            .toAddress("0xaa")
            .quantityValue("0")
            .tokenQuantityLabelKey("approval-token-quantity")
        let m = base.mergeOver(override)
        XCTAssertEqual(m.action, "Approve A")
        XCTAssertEqual(m.fromTokenContract, "0xaa")
        XCTAssertNil(m.toTokenContract)
        XCTAssertEqual(m.toAddress, "0xaa")
        XCTAssertEqual(m.quantityValue, "0")
        XCTAssertEqual(m.tokenQuantityLabelKey, "approval-token-quantity")
        XCTAssertEqual(base.mergeOver(nil).action, "Swap A for B")
    }

    func testContractIsTokenInheritedOnlyWhenOverrideSetsContract() {
        let base = ReviewSpec().contractAddress("0xrouter").contractIsToken(false)
        let keep = base.mergeOver(ReviewSpec().action("x").contractIsToken(true))
        XCTAssertFalse(keep.contractIsToken)
        let swap = base.mergeOver(ReviewSpec().contractAddress("0xtoken").contractIsToken(true))
        XCTAssertTrue(swap.contractIsToken)
        XCTAssertEqual(swap.contractAddress, "0xtoken")
    }

    func testGasSetsBothRows() {
        let s = ReviewSpec().gas(84_000, "0.4 Q")
        XCTAssertEqual(s.gasLimit, 84_000)
        XCTAssertEqual(s.gasFeeLabel, "0.4 Q")
    }
}

final class TxStatusPollerTests: XCTestCase {

    private func tx(_ hash: String, status: String?) throws -> AccountTransaction {
        var obj: [String: Any] = ["hash": hash]
        if let status { obj["status"] = status }
        let data = try JSONSerialization.data(withJSONObject: obj)
        return try JSONDecoder().decode(AccountTransaction.self, from: data)
    }

    func testIsSuccessMatrix() {
        XCTAssertTrue(TxStatusPoller.isSuccess(true))
        XCTAssertTrue(TxStatusPoller.isSuccess(1))
        XCTAssertTrue(TxStatusPoller.isSuccess("0x1"))
        XCTAssertTrue(TxStatusPoller.isSuccess(" 1 "))
        XCTAssertTrue(TxStatusPoller.isSuccess("TRUE"))
        XCTAssertFalse(TxStatusPoller.isSuccess(false))
        XCTAssertFalse(TxStatusPoller.isSuccess("0x0"))
        XCTAssertFalse(TxStatusPoller.isSuccess(0))
        XCTAssertFalse(TxStatusPoller.isSuccess(nil))
    }

    func testStatusMapping() throws {
        let h = "0xABC"
        XCTAssertEqual(TxStatusPoller.status(pending: [try tx(h, status: nil)], completed: [], txHash: "0xabc"), .pending)
        XCTAssertEqual(TxStatusPoller.status(pending: [], completed: [try tx(h, status: "0x1")], txHash: "0xabc"), .succeeded)
        XCTAssertEqual(TxStatusPoller.status(pending: [], completed: [try tx(h, status: "0x0")], txHash: "0xabc"), .failed)
        XCTAssertEqual(TxStatusPoller.status(pending: [], completed: [try tx("0xother", status: "0x1")], txHash: "0xabc"), .unknown)
        XCTAssertEqual(TxStatusPoller.status(pending: [], completed: [], txHash: "0xabc"), .unknown)
    }
}

final class UrlBuilderTokenTests: XCTestCase {

    private let valid = "0x" + String(repeating: "ab", count: 32)

    func testTokenUrlComposition() {
        let url = UrlBuilder.blockExplorerTokenUrl(base: "https://quantumscan.com", address: valid)
        XCTAssertEqual(url?.absoluteString, "https://quantumscan.com/token/\(valid)")
    }

    func testTokenUrlRejectsInvalidAddress() {
        XCTAssertNil(UrlBuilder.blockExplorerTokenUrl(base: "https://quantumscan.com", address: "0x12"))
        XCTAssertNil(UrlBuilder.blockExplorerTokenUrl(base: "https://quantumscan.com", address: "../etc"))
    }

    func testAccountUrlStillUsesTxnPage() {
        let url = UrlBuilder.blockExplorerAccountUrl(base: "https://quantumscan.com", address: valid)
        XCTAssertEqual(url?.absoluteString, "https://quantumscan.com/account/\(valid)/txn/page")
    }
}
