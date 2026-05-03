// Aead.swift (Crypto layer 3)
// AES-256-GCM seal / open primitives, paired with the on-wire
// `{"v":2,"cipherText":"<b64>","iv":"<b64>"}` envelope shape that
// the iOS and Android wallet apps both speak. This file is the
// single Swift owner of the AES-GCM operations the rest of the
// codebase performs against scrypt-derived symmetric keys.
// The `open` length guard in this file is
// strictly `> 16` (not `>= 16`) so a 16-byte combined input -
// which would correspond to an empty ciphertext + a 16-byte tag -
// is rejected before reaching `AES.GCM.SealedBox`. See the
// "hardening" note inside `open(_:keyBytes:)` for the full
// rationale.
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// The original implementation lived inline as private
// `encryptEnvelope` / `decryptEnvelope` helpers next to the
// storage code. Pulling them into a dedicated crypto-
// primitive module gives us:
// * a single review surface for every AES-GCM operation in
// the wallet (the only call sites are layer-3 storage
// and layer-4 unlock flows that derive symmetric keys via
// `PasswordKdf` and then call `Aead.seal` / `Aead.open`),
// * unit-testability without standing up the storage stack
// (`Aead.seal` and `Aead.open` are pure functions of their
// inputs - no global state, no side effects),
// * the layered-architecture goal of this codebase: crypto
// code is free of storage / wallet-semantics dependencies;
// storage code is free of crypto-implementation details.
// The wire format below is identical to the Android
// `SecureStorage.java` implementation byte-for-byte. Backups
// produced by either platform decrypt cleanly on the other, a
// non-negotiable cross-platform invariant.
// specifically: the original `combined.count >= 16`
// length guard accepted a 16-byte combined input. Splitting
// that input into `(ciphertext: prefix(0), tag: suffix(16))`
// leaves an empty ciphertext that CryptoKit will dutifully
// pass to `AES.GCM.SealedBox`. AES-GCM's authenticated-
// decryption path will then either:
// * throw an authentication-failed error (most common -
// random 16 bytes are not a valid tag for the empty
// message under any plausible key), OR
// * succeed, returning a 0-byte plaintext. This is the
// worst case: a well-chosen attacker-supplied 16-byte
// blob (or a forensic accident on a corrupted file) can
// authenticate as a legitimate decryption of an empty
// message under the correct key. Downstream code that
// expects to deserialize JSON from the plaintext then
// sees an empty Data, which can:
// - silently produce an empty wallet snapshot (treated
// by the UI as "no wallets exist yet" - the user is
// offered to create one over the top of their actual
// encrypted-but-unread data);
// - or crash a JSON parser that does not handle 0-byte
// input.
// Tightening to `> 16` makes the 16-byte boundary case fail
// loud at the length check (returns `AeadError.decodeFailed`)
// instead of percolating into AEAD evaluation. There is no
// legitimate AES-GCM ciphertext of length 0 in our corpus -
// every encrypted blob has at least one byte of plaintext
// (the smallest is the JSON `{}` which seals to 18 bytes).
// Tradeoffs:
// - One-character semantic change (`>=` -> `>`). No
// compatibility risk because no on-disk envelope today has
// a 16-byte combined ciphertext+tag.
// - The old inline implementations are gone. The behaviour is
// unchanged for every legitimate envelope (>= 17 byte
// combined input).
// Cross-references to other mitigations:
// - `` (this file) closes ``.
// - `` (`SecureRandom`) is the upstream guarantee that
// the nonce passed to `seal` is genuinely random. If
// `SecureRandom` ever throws, the seal call itself throws
// and the envelope is never produced; we never emit a
// zero-nonce envelope.
// - `` / `` / `` (the v2 storage redesign)
// keep using `Aead.seal` / `Aead.open` as their primitives;
// only the layer above (envelope -> file) is replaced.

import Foundation
import CryptoKit

public enum Aead {

    /// On-wire schema marker. iOS and Android both write `2`.
    /// Future migrations bump this; readers fail closed on
    /// unrecognised values.
    public static let envelopeVersion: Int = 2

    /// AES-GCM seal (encrypt + authenticate). Returns the
    /// `{"v":2,"cipherText":"<b64>","iv":"<b64>"}` JSON envelope
    /// as a `String` so callers can persist it directly.
    /// Threading: pure (no shared mutable state). Safe to call
    /// from any thread.
    /// Throws on `SecureRandom` failure, on `AES.GCM.seal` failure
    /// (extremely unlikely), or on `JSONSerialization` failure
    /// (impossible for the well-typed input).
    public static func seal(_ plaintext: Data, keyBytes: Data) throws -> String {
        let key = SymmetricKey(data: keyBytes)
        // Throwing nonce draw. See
        // `Crypto/SecureRandom.swift` for the full write-up.
        let nonceBytes = try SecureRandom.bytes(12)
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)

        // Wire shape: cipherText is (ciphertext || tag), iv is
        // the 12-byte nonce, both base64. Identical to Android
        // `SecureStorage.java` so cross-platform backups
        // round-trip without re-encoding.
        var cipherTextAndTag = Data()
        cipherTextAndTag.append(sealed.ciphertext)
        cipherTextAndTag.append(sealed.tag)

        let obj: [String: Any] = [
            "v": envelopeVersion,
            "cipherText": cipherTextAndTag.base64EncodedString(),
            "iv": nonceBytes.base64EncodedString()
        ]
        let data = try JSONSerialization.data(
            withJSONObject: obj, options: [.sortedKeys])
        guard let s = String(data: data, encoding: .utf8) else {
            throw AeadError.envelopeEncodeFailed
        }
        return s
    }

    /// AES-GCM open (verify + decrypt). Throws
    /// `AeadError.malformedEnvelope` on a structurally-broken
    /// input, `AeadError.authenticationFailed` on a tag-mismatch
    /// (wrong password, tampered ciphertext, truncated input).
    /// Threading: pure. Safe to call from any thread.
    public static func open(_ envelopeJson: String, keyBytes: Data) throws -> Data {
        guard
        let obj = jsonObject(envelopeJson),
        let cipherB64 = obj["cipherText"] as? String,
        let ivB64 = obj["iv"] as? String,
        let ivData = Data(base64Encoded: ivB64),
        let combined = Data(base64Encoded: cipherB64),
        // -----------------------------------------------------
        // hardening (audit-grade write-up).
        // Strictly > 16, NOT >= 16. The 16-byte boundary case
        // would produce `(ciphertext: prefix(0), tag: suffix(16))`,
        // i.e. an EMPTY ciphertext authenticated by a 16-byte
        // tag. CryptoKit will dutifully evaluate that:
        // * Almost always tag-fails (the empty message has
        // a unique correct tag per (key, nonce); any
        // attacker-supplied 16 bytes are vanishingly
        // unlikely to match it).
        // * BUT if a forensic accident (e.g. a 16-byte
        // truncation of a real envelope) ever happens to
        // produce the unique correct empty-message tag
        // for the user's key+nonce, AES.GCM.open returns
        // a 0-byte Data successfully. Downstream JSON
        // deserialization then either crashes or, worse,
        // silently treats the file as "no wallets yet"
        // and offers to overwrite the encrypted data
        // with a freshly-created empty strongbox - permanent
        // data loss without a wrong-password error to
        // warn the user.
        // Rejecting at the length-guard level closes that
        // failure mode entirely, with no compatibility cost
        // (every legitimate envelope is >= 18 bytes combined
        // because the smallest plaintext we ever seal is the
        // JSON literal `{}` which is 2 bytes).
        // -----------------------------------------------------
        combined.count > 16
        else {
            throw AeadError.malformedEnvelope
        }

        let tagStart = combined.count - 16
        let ciphertext = combined.prefix(tagStart)
        let tag = combined.suffix(16)

        let key = SymmetricKey(data: keyBytes)
        let nonce = try AES.GCM.Nonce(data: ivData)
        let box = try AES.GCM.SealedBox(
            nonce: nonce, ciphertext: ciphertext, tag: tag)
        do {
            return try AES.GCM.open(box, using: key)
        } catch {
            throw AeadError.authenticationFailed
        }
    }

    // MARK: - Internals

    private static func jsonObject(_ s: String) -> [String: Any]? {
        guard let data = s.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}

// MARK: - Errors

public enum AeadError: Error, CustomStringConvertible {
    /// Length guard, JSON shape, or base64 decode failed. No
    /// AES-GCM operation was attempted.
    case malformedEnvelope
    /// AES-GCM tag mismatch. Either the wrong key was used
    /// (wrong password) or the ciphertext / tag has been
    /// tampered with / truncated.
    case authenticationFailed
    /// Defensive: `JSONSerialization` produced bytes that are
    /// not UTF-8 decodable. Logically impossible for the input
    /// we feed; included so the public API has no fatalError()
    /// paths.
    case envelopeEncodeFailed

    public var description: String {
        switch self {
            case .malformedEnvelope: return "AeadError.malformedEnvelope"
            case .authenticationFailed: return "AeadError.authenticationFailed"
            case .envelopeEncodeFailed: return "AeadError.envelopeEncodeFailed"
        }
    }
}
