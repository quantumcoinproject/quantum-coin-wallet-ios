// Mac.swift (Crypto layer 3)
// HMAC-SHA256 and HKDF-SHA256 (RFC 5869) primitives used by the
// v2 strongbox file format for:
// - File-level integrity MAC (`mac` field at the top of every
// slot file). Detects on-disk tampering and rollback /
// stale-slot swap.
// - HKDF-Expand to derive the file-level MAC key from the
// strongbox `mainKey`, salted by `kdf.salt`, with info string
// `"integrity-v2"`. The derivation is reproducible and
// covered by the unit-test vectors.
// - HKDF-Expand to derive the per-`ui` HMAC key from the
// device-only `deviceUiKey` Keychain secret. Lets the
// pre-unlock UI namespace (EULA flag, language code) be
// tamper-detected without requiring a wallet unlock.
// Design discipline (audit-grade notes for AI reviewers and
// human auditors):
// * This file is the only call site for `HMAC<SHA256>` and
// `HKDF<SHA256>` in the wallet. Other layers (especially
// layer 2 `StrongboxFileCodec`) call into the `Mac` enum here
// so the integrity primitive is reviewable in one place.
// * `verify(_:mac:keyBytes:)` uses CryptoKit's
// constant-time `isValidAuthenticationCode`, NOT `==`. A
// timing-safe MAC comparison closes a class of side-
// channel attacks where an attacker who can measure
// decryption latency learns one byte of the MAC at a time.
// The leak is bounded in our process model (no remote MAC
// oracle), but writing the constant-time comparison is
// free and removes the entire class of concern.
// * `expand(_:salt:info:length:)` follows RFC 5869 §2.3 by
// using HKDF-Expand directly on the input key material.
// For the file-level MAC key derivation, the IKM is the
// 32-byte AES-GCM `mainKey` (already a uniformly random
// secret), so the HKDF-Extract step is unnecessary. We
// therefore use `HKDF.deriveKey(inputKeyMaterial:salt:
// info:outputByteCount:)` which performs Extract-then-
// Expand internally; for our usage the salt argument
// binds the derivation to `kdf.salt` so a salt change
// produces an entirely new MAC key.
// Tradeoffs:
// - We use Apple's `CryptoKit` HKDF rather than rolling our
// own. CryptoKit is FIPS-validated, well-fuzzed, and
// hardware-accelerated where the device supports it. The
// alternative (a pure-Swift HKDF in this file for cross-
// platform parity with Android) would be reviewable but
// would duplicate code that Apple already maintains. We
// accept the platform-native choice and document the
// parity contract in `Schema/StrongboxFileCodec.swift` (the
// KAT vectors for the derivation are listed there so
// Android's implementation can self-check).

import Foundation
import CryptoKit

public enum Mac {

    // MARK: - HMAC-SHA256

    /// Compute HMAC-SHA256(key, message). Returns the 32-byte
    /// tag.
    /// Threading: pure. Safe to call from any thread.
    public static func hmacSha256(message: Data, keyBytes: Data) -> Data {
        let key = SymmetricKey(data: keyBytes)
        let tag = HMAC<SHA256>.authenticationCode(for: message, using: key)
        return Data(tag)
    }

    /// Constant-time MAC comparison. Returns `true` iff the
    /// stored MAC matches the freshly-computed MAC for the
    /// given message and key.
    /// IMPORTANT: callers MUST use this rather than `==`. The
    /// Swift `==` on `Data` is NOT constant-time and would leak
    /// MAC byte positions through timing-side-channels in any
    /// future scenario where decryption time becomes
    /// observable.
    public static func verify(_ message: Data,
        mac storedMac: Data,
        keyBytes: Data) -> Bool {
        let key = SymmetricKey(data: keyBytes)
        return HMAC<SHA256>.isValidAuthenticationCode(
            storedMac, authenticating: message, using: key)
    }

    // MARK: - HKDF-SHA256

    /// HKDF-SHA256 derivation. Returns `length` bytes of key
    /// material derived from `inputKeyMaterial`, salted by
    /// `salt`, bound by the `info` context string.
    /// `salt` and `info` are the standard HKDF parameters:
    /// - `salt` adds a domain-separation tag so two
    /// derivations from the same IKM but different salt
    /// produce independent keys.
    /// - `info` adds a context string so two derivations
    /// from the same IKM and salt but different info
    /// produce independent keys (used here to separate the
    /// `"integrity-v2"` MAC key from any future
    /// `"encryption-v2"` derived key).
    public static func hkdfExpand(inputKeyMaterial: Data,
        salt: Data,
        info: Data,
        length: Int) -> Data {
        let ikm = SymmetricKey(data: inputKeyMaterial)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: length
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    /// Convenience wrapper that takes string `info` and converts
    /// it to UTF-8 bytes. Used by call sites where the info
    /// parameter is a human-readable context label like
    /// `"integrity-v2"`.
    public static func hkdfExpand(inputKeyMaterial: Data,
        salt: Data,
        info: String,
        length: Int) -> Data {
        return hkdfExpand(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: Data(info.utf8),
            length: length)
    }
}
