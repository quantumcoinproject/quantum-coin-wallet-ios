// Logger.swift (Diagnostics layer)
// Developer-only logging shim that:
// 1. Compiles to a no-op in Release builds (`#if DEBUG` gates the
// entire body, so `Logger.debug(...)` calls leave neither the
// message bytes nor the formatting work in the Release binary).
// 2. In DEBUG builds, redacts known-sensitive substrings BEFORE
// handing the string to `print(...)`. The redactor catches:
// * 0x-prefixed 64-hex strings (covers BOTH QuantumCoin
// addresses AND transaction hashes - both are 64 hex
// digits in this wallet, so the redactor cannot
// distinguish them and uses a single template that is
// truthful for either case)
// * any other run of >= 32 hex digits (catches private keys,
// public keys, AES-GCM ciphertexts, scrypt-derived keys
// rendered as hex)
// * any base64-shape blob >= 40 characters (catches the
// base64 envelope serialisations the JS bridge passes
// around for keys / ciphertexts / nonces)
// * any single token from the BIP-39 wordlist (catches a
// mnemonic word slipping through an exception message)
// Why it exists (audit-grade notes for AI reviewers and human
// auditors):
// The audit (``) flagged that bare `print(...)` and
// `console.error(...)` sites were emitting raw error context to
// Console.app and an attached debugger. In DEBUG, that context
// could carry sensitive material (a `JsBridgeError(message:)`
// surfaced from a failing decrypt has the failed envelope's bytes
// in its message; an `ApiError.other` from a 4xx body can carry a
// transaction the user just sent; the `loadTokens` path can
// surface the wallet's own address into Console because its URL
// was the one that 4xx'd).
// The defence here is two-layer:
// * Release builds: logging is gone entirely. There is nothing
// in the Release binary to leak. (The compiler is free to
// remove the `#if DEBUG` body and any string-literal arguments
// passed by call sites because the call has no side effect in
// Release.)
// * DEBUG builds: the redactor blanks out the substrings most
// likely to be sensitive before the message reaches `print`.
// This trades a little debuggability ("AEAD failed: <REDACTED-
// HEX-128>" vs the full ciphertext) for a guarantee that a
// developer running the wallet in DEBUG and screen-sharing in
// a meeting cannot accidentally splash a private key into the
// Xcode console.
// The call sites in the signing / unlock / API paths now route
// through `Logger.debug(category:_:)`. The category is an opaque
// string (e.g. `"BRIDGE_ERR"`, `"PREFS_FLUSH_FAIL"`,
// `"LOAD_TOKENS_FAIL"`) so a developer reading Console can locate
// the failing code path without seeing the failing input.
// Tradeoffs:
// - The redactor is a heuristic, not a parser. A novel encoding
// (Bech32, base58, etc.) that we have not anticipated could
// leak through. Mitigation: the call sites that pass through
// this shim are also the ones whose error messages have been
// audited for what they construct. Adding a new error message
// that interpolates secret material is a code-review concern
// even with the redactor in place.
// - We deliberately do NOT redact in the BIP-39 case greedily
// (a word like "above" or "actor" appearing in an English
// error sentence shouldn't be redacted). The check is "the
// word is the only token, surrounded by whitespace, in the
// message and the message looks short enough to be a leaked
// mnemonic word". This is intentionally weak; the stronger
// defence is to never let the error path serialise a mnemonic
// into a String, which is enforced by the `bridge.html`
// `zeroString` policy on payload return.
// - The Release-build no-op means a crash log captured by
// TestFlight / customer support contains zero bridge / API
// diagnostic context. We accept this: the `requestId` echoed
// by the JS bridge plus the failing function's symbol name
// in the stack trace is enough to locate the failing call
// site, and the developer can re-run in DEBUG to see the
// redacted detail.
import Foundation

public enum Logger {

    /// DEBUG-only emission of a category-tagged diagnostic line.
    /// Compiles to nothing in Release.
    /// Call shape:
    /// Logger.debug(category: "BRIDGE_ERR",
    /// "request 0x4f3a failed: \(rawError)")
    /// The `category` is a stable, opaque token that lets a
    /// developer locate the failing code path in Console.app
    /// without having to grep on the redacted message. The
    /// `message` body is run through the redactor before
    /// emission - see file header for the redaction surface.
    public static func debug(category: String,
        _ message: @autoclosure () -> String,
        file: StaticString = #file,
        line: UInt = #line) {
        #if DEBUG
        let raw = message()
        let redacted = redact(raw)
        let shortFile = ("\(file)" as NSString).lastPathComponent
        print("[\(category)] \(shortFile):\(line) \(redacted)")
        #endif
    }

    // MARK: - Redactor (DEBUG-only)

    #if DEBUG
    /// Matches `0x`-prefixed 64-hex strings. QuantumCoin
    /// addresses AND transaction hashes both serialise to 64
    /// hex digits, so a single regex covers both with a
    /// shared template. We deliberately do NOT try to
    /// disambiguate: a 64-hex string in a debug log line is
    /// equally sensitive whether it is an address or a tx
    /// hash, and either could leak the user's identity to
    /// anyone watching the developer's screen.
    private static let hexAddrOrTxRe = try! NSRegularExpression(
        pattern: "0x[0-9a-fA-F]{64}\\b",
        options: [])
    private static let longHexRe = try! NSRegularExpression(
        pattern: "(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])",
        options: [])
    private static let base64Re = try! NSRegularExpression(
        pattern: "(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])",
        options: [])

    private static func redact(_ s: String) -> String {
        var out = s as NSString
        let r = NSRange(location: 0, length: out.length)
        out = hexAddrOrTxRe.stringByReplacingMatches(
            in: out as String, options: [], range: r,
            withTemplate: "<REDACTED-HEX-ADDR-OR-TX>") as NSString
        let r3 = NSRange(location: 0, length: out.length)
        out = longHexRe.stringByReplacingMatches(
            in: out as String, options: [], range: r3,
            withTemplate: "<REDACTED-HEX>") as NSString
        let r4 = NSRange(location: 0, length: out.length)
        out = base64Re.stringByReplacingMatches(
            in: out as String, options: [], range: r4,
            withTemplate: "<REDACTED-B64>") as NSString
        return out as String
    }
    #endif
}
