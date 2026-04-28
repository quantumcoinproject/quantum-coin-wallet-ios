//
// CoinUtils.swift
//
// Pure-Swift wei -> ether string formatter. Mirrors the Android
// `CoinUtils.formatWei` helper byte-for-byte so the Confirm Wallet
// screen and the main wallet header agree with the Android UX.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/utils/CoinUtils.java
//
// Wei amounts can exceed 2^128 (BigInteger on Android), so we avoid
// `Decimal` (38 digits) and `Double` (15 digits) and instead operate
// on the digit string directly: pad to 18 fractional digits, insert
// the decimal point, then strip leading + trailing zeros.
//

import Foundation

public enum CoinUtils {

    /// Number of wei in one ether (10^18).
    public static let ETHER_DECIMALS: Int = 18

    /// Convert a decimal-string wei value to a human-readable ether
    /// amount. Null / empty / non-numeric input returns "0".
    public static func formatWei(_ weiValue: String?) -> String {
        return formatUnits(weiValue, decimals: ETHER_DECIMALS)
    }

    /// Convert a wei-like value (decimal or 0x-prefixed hex) to a
    /// human-readable amount with the supplied decimal scale. Mirrors
    /// `ethers.formatUnits`.
    public static func formatUnits(_ value: String?, decimals: Int) -> String {
        guard let raw = value?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return "0"
        }
        var sign = ""
        var work = raw
        if work.hasPrefix("-") { sign = "-"; work.removeFirst() }
        else if work.hasPrefix("+") { work.removeFirst() }

        var digits: String
        if work.hasPrefix("0x") || work.hasPrefix("0X") {
            let hex = String(work.dropFirst(2))
            guard !hex.isEmpty,
                  hex.allSatisfy({ $0.isHexDigit }),
                  let asDecimal = hexToDecimalString(hex) else {
                return "0"
            }
            digits = asDecimal
        } else {
            guard !work.isEmpty,
                  work.allSatisfy({ $0.isASCII && $0.isNumber }) else {
                return "0"
            }
            digits = work
        }

        // Strip leading zeros.
        let stripped = digits.drop(while: { $0 == "0" })
        digits = stripped.isEmpty ? "0" : String(stripped)
        if digits == "0" { return "0" }
        if decimals <= 0 { return sign + digits }

        let scale = decimals
        let s: String
        if digits.count > scale {
            let cut = digits.index(digits.endIndex, offsetBy: -scale)
            s = "\(digits[..<cut]).\(digits[cut...])"
        } else {
            let pad = String(repeating: "0", count: scale - digits.count)
            s = "0." + pad + digits
        }

        var result = s
        if result.contains(".") {
            while result.last == "0" { result.removeLast() }
            if result.last == "." { result.removeLast() }
        }
        if result.isEmpty { result = "0" }
        return sign + result
    }

    /// Convert an unsigned hex-digit string into its decimal-digit
    /// representation. Supports arbitrary length without falling back
    /// to fixed-precision math. Returns nil only on programmer error
    /// (already validated upstream).
    private static func hexToDecimalString(_ hex: String) -> String? {
        var digits: [UInt8] = [0]
        for ch in hex {
            guard let nibble = ch.hexDigitValue else { return nil }
            var carry = nibble
            for i in 0..<digits.count {
                let v = Int(digits[i]) * 16 + carry
                digits[i] = UInt8(v % 10)
                carry = v / 10
            }
            while carry > 0 {
                digits.append(UInt8(carry % 10))
                carry /= 10
            }
        }
        let s = digits.reversed().map { String($0) }.joined()
        return s.isEmpty ? "0" : s
    }
}
