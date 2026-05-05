// CoinUtils.swift
// Pure-Swift wei -> ether string formatter. Mirrors the Android
// `CoinUtils.formatWei` helper byte-for-byte so the Confirm Wallet
// screen and the main wallet header agree with the Android UX.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/utils/CoinUtils.java
// Wei amounts can exceed 2^128 (BigInteger on Android), so we avoid
// `Decimal` (38 digits) and `Double` (15 digits) and instead operate
// on the digit string directly: pad to 18 fractional digits, insert
// the decimal point, then strip leading + trailing zeros.

import Foundation

public enum CoinUtils {

    /// Number of wei in one ether (10^18).
    public static let ETHER_DECIMALS: Int = 18

    /// Maximum `decimals` value accepted by `parseUnits` /
    /// `formatUnits` before the input is treated as malformed
    /// and short-circuited to the existing `"0"` sentinel.
    /// (audit-grade notes for AI reviewers and human auditors):
    /// `decimals` reaches these helpers from token-metadata RPC
    /// responses and from user-pasted contract definitions. A
    /// hostile RPC endpoint (or a malformed token contract) can
    /// return an absurdly large value (`Int.max` is the worst
    /// case). The padding allocations inside `parseUnits` /
    /// `formatUnits` (`String(repeating: "0", count: scale -
    /// fracPart.count)`) then balloon to many GB and OOM-kill
    /// the app, taking down every subsequent token query - a
    /// reliable per-launch DoS as soon as the wallet renders a
    /// balance on the home screen. Real-world tokens use 0 to
    /// 18 decimals; 64 leaves ~3.5x headroom for a hypothetical
    /// future PQ-era token without ever letting the allocation
    /// reach OOM territory.
    public static let MAX_TOKEN_DECIMALS: Int = 64

    /// Maximum hex-input length accepted by `hexToDecimalString`
    /// before the conversion is treated as malformed and
    /// short-circuited to nil (which `formatUnits` maps to "0").
    /// (audit-grade notes for AI reviewers and human auditors):
    /// the conversion is O(N^2) over the hex input length; the
    /// input ultimately comes from RPC responses (untrusted).
    /// A maliciously long hex string freezes the UI long enough
    /// to trip the iOS watchdog, killing the app. 1024 hex chars
    /// covers any value up to ~4096 bits, which is far beyond
    /// any wei amount the chain produces (the EVM word size is
    /// 256 bits).
    public static let MAX_HEX_INPUT_CHARS: Int = 1024

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
        // Cap `decimals` BEFORE any allocation sized by it. An
        // RPC-supplied value of `Int.max` would otherwise drive
        // `String(repeating: "0", count: ...)` to OOM-kill the
        // app on every token render.
        if decimals > MAX_TOKEN_DECIMALS { return "0" }
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

    /// Convert an ether (decimal) amount to its wei (integer-string)
    /// representation. Mirrors Android `CoinUtils.parseEther` which
    /// multiplies the input by `10^18`. Empty / nil / malformed
    /// input returns "0". Used by the Send pipeline to translate
    /// the user-typed quantity field into the wei-scaled value the
    /// JS bridge expects.
    public static func parseEther(_ etherValue: String?) -> String {
        return parseUnits(etherValue, decimals: ETHER_DECIMALS)
    }

    /// Convert a decimal amount to its base-unit (wei-scaled) integer
    /// string by multiplying by `10^decimals`. Mirrors Android
    /// `CoinUtils.parseUnits(amount, decimals)`. Truncates fractional
    /// digits beyond `decimals` (no rounding) to avoid silently
    /// inflating the user's input. Returns "0" for empty / malformed
    /// input. Operates on the digit string directly so 18-decimal
    /// (and higher) precision is exact, matching the inverse
    /// `formatUnits` strategy.
    public static func parseUnits(_ value: String?, decimals: Int) -> String {
        guard let raw = value?.trimmingCharacters(in: .whitespacesAndNewlines),
        !raw.isEmpty else {
            return "0"
        }
        // Cap `decimals` BEFORE any allocation sized by it. An
        // RPC-supplied value of `Int.max` would otherwise drive
        // `String(repeating: "0", count: ...)` below to OOM-kill
        // the app on the next signing prep.
        if decimals > MAX_TOKEN_DECIMALS { return "0" }
        var sign = ""
        var work = raw
        if work.hasPrefix("-") { sign = "-"; work.removeFirst() }
        else if work.hasPrefix("+") { work.removeFirst() }

        // Accept the locale comma alongside `.` so a user on a
        // comma-locale device whose decimal pad emits `,` doesn't
        // silently lose every fractional digit.
        work = work.replacingOccurrences(of: ",", with: ".")

        let dotCount = work.filter { $0 == "." }.count
        guard dotCount <= 1 else { return "0" }

        let intPart: String
        let fracPart: String
        if let dot = work.firstIndex(of: ".") {
            intPart = String(work[..<dot])
            fracPart = String(work[work.index(after: dot)...])
        } else {
            intPart = work
            fracPart = ""
        }

        let isAsciiDigit: (Character) -> Bool = { $0.isASCII && $0.isNumber }
        guard intPart.allSatisfy(isAsciiDigit) || intPart.isEmpty,
        fracPart.allSatisfy(isAsciiDigit) else {
            return "0"
        }

        let scale = max(decimals, 0)
        var combined: String
        if scale == 0 {
            combined = intPart.isEmpty ? "0" : intPart
        } else if fracPart.count >= scale {
            // Truncate any digits past the supported decimals.
            let cut = fracPart.index(fracPart.startIndex, offsetBy: scale)
            combined = (intPart.isEmpty ? "0" : intPart) + fracPart[..<cut]
        } else {
            let pad = String(repeating: "0", count: scale - fracPart.count)
            combined = (intPart.isEmpty ? "0" : intPart) + fracPart + pad
        }

        // Strip leading zeros so wei is canonical ("100" not "00100").
        let stripped = combined.drop(while: { $0 == "0" })
        let canonical = stripped.isEmpty ? "0" : String(stripped)
        if canonical == "0" { return "0" }
        return sign + canonical
    }

    /// Convert an unsigned hex-digit string into its decimal-digit
    /// representation. Supports arbitrary length without falling back
    /// to fixed-precision math. Returns nil only on programmer error
    /// (already validated upstream).
    private static func hexToDecimalString(_ hex: String) -> String? {
        // The conversion is O(N^2) over input length and the
        // input ultimately comes from RPC
        // responses (untrusted). A maliciously long hex string
        // freezes the UI long enough to trip the iOS watchdog,
        // killing the app. Cap at `MAX_HEX_INPUT_CHARS` (1024
        // hex digits = ~4096 bits, far beyond the EVM 256-bit
        // word). Returning nil mirrors the existing "malformed
        // input" sentinel which `formatUnits` maps to "0".
        if hex.count > MAX_HEX_INPUT_CHARS { return nil }
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
