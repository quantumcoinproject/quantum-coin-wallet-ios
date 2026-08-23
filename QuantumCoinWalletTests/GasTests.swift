// GasTests.swift
// Mirrors Android GasBufferTest + GasFeeTest so both platforms pin the
// same desktop gas numbers.

import XCTest
@testable import QuantumCoinWallet

final class GasKindTests: XCTestCase {

    func testCoinSendHasNoBuffer() {
        XCTAssertEqual(GasKind.sendCoin.bufferPercent, 0)
        XCTAssertEqual(GasKind.sendCoin.applyBuffer(21_000), 21_000)
    }

    func testEveryOtherKindAddsTenPercent() {
        for k in GasKind.allCases where k != .sendCoin {
            XCTAssertEqual(k.bufferPercent, 10, k.rawValue)
            XCTAssertEqual(k.applyBuffer(100_000), 110_000, k.rawValue)
            // floor(raw * 110 / 100), same integer math as desktop applyGasBuffer
            XCTAssertEqual(k.applyBuffer(15), 16, k.rawValue)
        }
    }

    func testDesktopDefaults() {
        XCTAssertEqual(GasKind.sendCoin.defaultGas, 21_000)
        XCTAssertEqual(GasKind.sendToken.defaultGas, 84_000)
        XCTAssertEqual(GasKind.approve.defaultGas, 84_000)
        XCTAssertEqual(GasKind.approveToken.defaultGas, 84_000)
        XCTAssertEqual(GasKind.swap.defaultGas, 200_000)
        XCTAssertEqual(GasKind.addLiquidity.defaultGas, 600_000)
        XCTAssertEqual(GasKind.removeLiquidity.defaultGas, 600_000)
        XCTAssertEqual(GasKind.createPair.defaultGas, 4_500_000)
        XCTAssertEqual(GasKind.deployToken.defaultGas, 6_000_000)
        XCTAssertEqual(GasKind.addLiquidity.defaultFor(pairExists: false), 4_500_000)
        XCTAssertEqual(GasKind.addLiquidity.defaultFor(pairExists: true), 600_000)
        XCTAssertEqual(GasKind.swap.defaultFor(pairExists: false), 200_000)
    }

    func testTxKindMatchesBridgeDispatch() {
        XCTAssertEqual(GasKind.sendCoin.txKind, "sendCoin")
        XCTAssertEqual(GasKind.approveToken.txKind, "approveToken")
        XCTAssertEqual(GasKind.deployToken.txKind, "deployToken")
    }
}

final class GasFeeTests: XCTestCase {

    func testGasPriceKeyType3NoFullSignIsBase() {
        XCTAssertEqual(GasFee.gasPriceWei(keyType: 3, fullSign: false), Decimal(4_761_904_761_904_760))
    }

    func testGasPriceKeyType3FullSignIs30x() {
        XCTAssertEqual(GasFee.gasPriceWei(keyType: 3, fullSign: true), Decimal(4_761_904_761_904_760) * 30)
    }

    func testGasPriceKeyType5Is20xRegardlessOfFullSign() {
        XCTAssertEqual(GasFee.gasPriceWei(keyType: 5, fullSign: false), Decimal(4_761_904_761_904_760) * 20)
        XCTAssertEqual(GasFee.gasPriceWei(keyType: 5, fullSign: true), Decimal(4_761_904_761_904_760) * 20)
    }

    func testFeeQCoinSendKeyType3TruncatesTo6dp() {
        XCTAssertEqual(GasFee.feeQ(gasLimit: 21_000, keyType: 3, fullSign: false), Decimal(string: "99.999999"))
    }

    func testFeeQFormatsLikeDesktop() {
        XCTAssertEqual(GasFee.formatNumber(GasFee.feeQ(gasLimit: 21_000, keyType: 3, fullSign: false)), "100")
        XCTAssertEqual(GasFee.formatNumber(GasFee.feeQ(gasLimit: 21_000, keyType: 3, fullSign: true)), "3000")
        XCTAssertEqual(GasFee.formatNumber(GasFee.feeQ(gasLimit: 21_000, keyType: 5, fullSign: false)), "2000")
        XCTAssertEqual(GasFee.formatQ(GasFee.feeQ(gasLimit: 21_000, keyType: 3, fullSign: false)), "100 Q")
    }

    func testFormatNumberTrimsTrailingZerosAndDot() {
        XCTAssertEqual(GasFee.formatNumber(Decimal(string: "0.476200")!), "0.4762")
        XCTAssertEqual(GasFee.formatNumber(Decimal(string: "110.0000")!), "110")
        XCTAssertEqual(GasFee.formatNumber(Decimal(string: "0.5")!), "0.5")
        XCTAssertEqual(GasFee.formatNumber(Decimal(0)), "0")
        XCTAssertEqual(GasFee.formatNumber("0.047619"), "0.0476")
    }

    func testFeeQNegativeLimitClampsToZero() {
        XCTAssertEqual(GasFee.feeQ(gasLimit: -5, keyType: 3, fullSign: false), Decimal(0))
    }

    func testKeyTypeFromPublicKeyByteCount() {
        XCTAssertEqual(GasFee.keyType(fromPublicKeyByteCount: 1408), 3)
        XCTAssertEqual(GasFee.keyType(fromPublicKeyByteCount: 2688), 5)
        XCTAssertEqual(GasFee.keyType(fromPublicKeyByteCount: 7), 3)
    }
}
