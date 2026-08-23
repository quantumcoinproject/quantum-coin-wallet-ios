// GasFee.swift
// Deterministic gas-fee math (desktop gas-fee-core.ts). No RPC: the
// fee is gasLimit x gasPrice where gasPrice depends on the wallet's
// key type and the "advanced signing" (full-sign) setting.
// Android reference: app/src/main/java/com/quantumswap/app/gas/GasFee.java

import Foundation

public enum GasFee {

    /// SDK dynamic base gas price (wei).
    public static let sdkDynamicBaseGasPriceWei: Decimal = 4_761_904_761_904_760
    public static let feeUnit = "Q"
    public static let keyType3 = 3
    public static let keyType5 = 5
    public static let defaultKeyType = 3
    public static let publicKeyLengthKeyType3 = 1408
    public static let publicKeyLengthKeyType5 = 2688

    private static let wei: Decimal = 1_000_000_000_000_000_000

    /// keyType 5 -> base x 20 (regardless of fullSign);
    /// keyType 3 -> base x 30 when fullSign else x 1.
    public static func gasPriceWei(keyType: Int, fullSign: Bool) -> Decimal {
        if keyType == keyType5 { return sdkDynamicBaseGasPriceWei * 20 }
        return sdkDynamicBaseGasPriceWei * (fullSign ? 30 : 1)
    }

    /// Fee in Q truncated to 6 decimals (desktop integer math:
    /// limit * price * 1e6 / 1e18, floor). Negative limits clamp to 0.
    public static func feeQ(gasLimit: Int64, keyType: Int, fullSign: Bool) -> Decimal {
        let limit = Decimal(max(gasLimit, 0))
        let scaled = limit * gasPriceWei(keyType: keyType, fullSign: fullSign) * 1_000_000 / wei
        var src = scaled
        var out = Decimal()
        NSDecimalRound(&out, &src, 0, .down)
        return out / 1_000_000
    }

    /// 4 dp HALF_UP, trailing zeros and dangling dot stripped:
    /// 0.476200 -> "0.4762", 110.0000 -> "110", 0 -> "0".
    public static func formatNumber(_ value: Decimal) -> String {
        var src = value
        var rounded = Decimal()
        NSDecimalRound(&rounded, &src, 4, .plain)
        var s = NSDecimalNumber(decimal: rounded).stringValue
        if s.contains(".") {
            while s.hasSuffix("0") { s.removeLast() }
            if s.hasSuffix(".") { s.removeLast() }
        }
        if s == "-0" || s.isEmpty { s = "0" }
        return s
    }

    public static func formatNumber(_ numberText: String) -> String {
        guard let d = Decimal(string: numberText.trimmingCharacters(in: .whitespaces)) else {
            return numberText
        }
        return formatNumber(d)
    }

    public static func formatQ(_ value: Decimal) -> String {
        formatNumber(value) + " " + feeUnit
    }

    public static func formatQ(_ numberText: String) -> String {
        formatNumber(numberText) + " " + feeUnit
    }

    /// Desktop resolveKeyType: public-key byte length decides the
    /// signature scheme; unknown lengths fall back to key type 3.
    public static func keyType(fromPublicKeyByteCount n: Int) -> Int {
        if n == publicKeyLengthKeyType5 { return keyType5 }
        if n == publicKeyLengthKeyType3 { return keyType3 }
        return defaultKeyType
    }

    private static func keyTypePrefKey(_ address: String) -> String {
        "WALLET_KEY_TYPE_" + address.lowercased()
    }

    public static func cachedKeyType(address: String) -> Int {
        let v = PrefConnect.shared.readInt(keyTypePrefKey(address), default: -1)
        return v == keyType3 || v == keyType5 ? v : defaultKeyType
    }

    public static func cacheKeyType(address: String, keyType: Int) {
        try? PrefConnect.shared.writeInt(keyTypePrefKey(address), keyType)
    }

    public static func fullSign() -> Bool {
        PrefConnect.shared.readBool(PrefKeys.ADVANCED_SIGNING_ENABLED_KEY)
    }

    /// Bare fee number for the wallet's cached key type + current
    /// advanced-signing setting (what the chip / review rows display).
    public static func feeNumberFor(gasLimit: Int64, address: String) -> String {
        formatNumber(feeQ(gasLimit: gasLimit, keyType: cachedKeyType(address: address),
                          fullSign: fullSign()))
    }
}
