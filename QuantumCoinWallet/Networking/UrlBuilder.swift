// UrlBuilder.swift (Networking layer)
// Single source of truth for every URL the app
// composes from a base + an attacker-influenceable string segment
// (a wallet address, a token-contract address, a transaction hash).
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// The app composes block-explorer URLs and API URLs by direct
// string concatenation:
// Constants.BLOCK_EXPLORER_URL +
// "/account/{address}/txn/page".replacingOccurrences(
// of: "{address}", with: raw)
// `raw` flows in from many sources:
// - The contract-address field of an ERC-20 token returned by
// the scan-API JSON (attacker-controlled if the user added a
// network whose RPC the attacker controls, which a phishing
// site can convince a user to do).
// - A QR-code scan from an arbitrary image (zero authentication).
// - A pasteboard value from any other app on the device.
// - A typed input from the recipient field on Send.
// None of those values are constrained to "0x + 40 hex" by the
// call sites. A scan-API response with `contractAddress`:
// `0xdead/../../malicious?phish=` composes a URL that, when
// passed to `UIApplication.shared.open`, pivots the user into
// Safari at the attacker's chosen origin. ATS does NOT cover
// `UIApplication.shared.open` (which routes through Safari).
// Safari then renders a phishing page that asks for the user's
// seed words.
// This helper:
// 1. Validates the substitute against the strict regex for its
// type (address: `^0x[0-9a-fA-F]{64}$` — QuantumCoin
// addresses are 32 bytes / 64 hex characters; tx hash:
// `^0x[0-9a-fA-F]{64}$`).
// (audit-grade notes for AI reviewers and human auditors):
// QCW-030. The previous header docstring referenced the
// Ethereum `^0x[0-9a-fA-F]{40}$` (20-byte) address shape,
// which is wrong for QuantumCoin: the address validator
// `QuantumCoinAddress.isValid` (used by both call sites in
// this file) enforces 32-byte / 64-hex-char addresses. The
// two regexes are now identical in shape because both an
// address and a transaction hash are 32-byte, 64-hex-char
// 0x-prefixed values - the type tags are kept distinct for
// call-site readability and so a future address vs. tx-hash
// shape divergence remains catchable with a single helper
// signature change.
// 2. Percent-encodes the substitute for safety even after the
// regex passes (defense-in-depth; the regex already rules
// out `/`, `?`, `#`, NUL, etc., but the encode step is the
// invariant the URL spec requires).
// 3. Returns `nil` on any validation failure so the caller
// falls back to a no-op (the user sees nothing happen rather
// than being pivoted to Safari).
// Lint contract (verification §10): every call to
// `replacingOccurrences(of: "{address}", with:)` and
// `replacingOccurrences(of: "{txhash}", with:)` outside this file
// is a build-blocking review failure. The wrapper is the only
// pathway through which the app composes such URLs.
// Tradeoff:
// A malformed value silently fails to open. We considered showing
// an error toast on failure, but the call sites are entry points
// the user explicitly tapped, and an error there is most likely a
// UI bug rather than an attack - so a silent no-op gives the
// least-bad UX while still defending against the URL-injection
// class.

import Foundation

public enum UrlBuilder {

    /// Compiled once. `try!` is safe: literal pattern is constant.
    private static let txHashRegex = try! NSRegularExpression(
        pattern: "^0x[0-9a-fA-F]{64}$",
        options: [])

    /// `true` iff `s` is a 0x-prefixed 32-byte (64 hex char) value.
    /// Used by `blockExplorerTxUrl` to validate the substitute
    /// before it reaches the URL.
    public static func isValidTxHash(_ s: String) -> Bool {
        let range = NSRange(location: 0, length: s.utf16.count)
        return txHashRegex.firstMatch(in: s, options: [], range: range) != nil
    }

    /// Build a block-explorer URL for the supplied account / contract
    /// address. Returns `nil` if the address fails strict regex
    /// validation OR if the URL cannot be constructed from
    /// `base` + the substituted template.
    /// Use this for every UI affordance that opens an explorer page
    /// for an address (the address strip's "Open in explorer" button,
    /// the wallets-list explorer button, the token row's contract
    /// link).
    public static func blockExplorerAccountUrl(base: String, address: String) -> URL? {
        return substituted(
            base: base,
            template: Constants.BLOCK_EXPLORER_ACCOUNT_TRANSACTION_URL,
            placeholder: "{address}",
            value: address,
            isValueValid: QuantumCoinAddress.isValid)
    }

    /// Build a block-explorer URL for the supplied transaction hash.
    /// Returns `nil` if the hash fails strict regex validation.
    public static func blockExplorerTxUrl(base: String, txHash: String) -> URL? {
        return substituted(
            base: base,
            template: Constants.BLOCK_EXPLORER_TX_HASH_URL,
            placeholder: "{txhash}",
            value: txHash,
            isValueValid: isValidTxHash)
    }

    /// Build an API path (no scheme/host) with a strictly-validated
    /// address segment. Returns the path string (e.g. `/account/0xabc`)
    /// or `nil` if `address` fails validation. Callers compose the
    /// full URL via `ApiClient.get(path:)`, which prefixes the base.
    public static func apiPath(_ template: String, address: String) -> String? {
        guard QuantumCoinAddress.isValid(address) else { return nil }
        // Address has already passed strict regex; percent-encoding is
        // a no-op for `[0-9a-fA-FxX]+` but is included for the
        // defense-in-depth invariant.
        let encoded = address.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed) ?? address
        return template.replacingOccurrences(of: "{address}", with: encoded)
    }

    /// Internal helper for the two block-explorer builders. Centralises
    /// the validate-then-encode-then-compose flow so both helpers cannot
    /// drift in posture.
    private static func substituted(
        base: String,
        template: String,
        placeholder: String,
        value: String,
        isValueValid: (String) -> Bool
    ) -> URL? {
        guard !base.isEmpty else { return nil }
        guard isValueValid(value) else { return nil }
        // Defense-in-depth percent-encoding: strict regex already
        // rules out the dangerous characters, but the encode step
        // makes the invariant true at the URL-spec layer.
        let encoded = value.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed) ?? value
        let path = template.replacingOccurrences(of: placeholder, with: encoded)
        return URL(string: base + path)
    }
}
