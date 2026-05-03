// StrongboxPadding.swift (Schema layer 2)
// Fixed-size 32 KiB bucket padding for the encrypted `strongbox`
// payload. Closes the size-leak half of ``.
// Why this exists (audit-grade notes for AI reviewers and
// human auditors):
// Without padding, the on-disk ciphertext length is
// approximately the plaintext length. An attacker who can
// read (but not decrypt) the slot file (the storage-medium
// exfiltration threat profile) can therefore distinguish:
// * 0 wallets (~ 200 bytes)
// * 1 wallet (~ 1.5 KiB)
// * 2 wallets (~ 3.0 KiB)
// * N wallets (linear in N())
// The wallet count is itself sensitive (it tells the
// attacker how high-value the target is, lets them know
// when to invest in a brute-force attempt, and reveals
// "this user has just added their first wallet" timing
// information from a backup diff).
// Padding to a fixed 32 KiB bucket means every slot file's
// `strongbox.ct` is exactly the same length regardless of how
// many wallets the user owns, up to 32 KiB of cleartext.
// That comfortably accommodates the realistic upper bound
// (~50 wallets * ~600 bytes/each + networks + UI prefs ~=
// 30 KiB worst-case). A user who legitimately exceeds the
// bucket will hit a clear "strongbox full" error rather than
// silently leak their wallet count by tripping into a
// larger bucket; that is the right failure mode for an
// asset-storage product.
// Format:
// padded = plaintext || 0x80 || 0x00 * (32768 - plaintext.count - 1)
// The 0x80 marker byte separates the plaintext from the
// zero pad. On unpad we walk backwards from the end:
// - skip trailing 0x00 bytes,
// - the next byte MUST be 0x80,
// - the bytes before it are the original plaintext.
// This is the ISO/IEC 7816-4 padding scheme (well-known,
// simple, and unambiguously reversible). It tolerates a
// plaintext length of 0..32767 inclusive.
// Tradeoffs:
// - Every write rewrites a full 32 KiB slot file even for a
// single-bool toggle. With 's two-slot rotation that
// is two flash sectors per write; on a modern iPhone the
// physical-write latency is ~ 5-10 ms. User-perceptible
// only if a user toggles a setting at >100 Hz, which
// never happens.
// - The 32 KiB bucket size is deliberately not parameterised:
// EVERY install must produce identical `strongbox.ct`
// lengths so a multi-device backup pair (the same user with
// two iPhones) cannot be distinguished by length alone. A
// device-specific bucket size would defeat that property.

import Foundation

public enum StrongboxPadding {

    /// Fixed plaintext bucket size in bytes. The matching
    /// `strongbox.ct.count` after AES-GCM seal is exactly this value
    /// (AES-GCM is a stream cipher and produces ciphertext of
    /// the same length as plaintext; the AEAD tag is stored
    /// separately as `strongbox.tag`).
    public static let bucketSize: Int = 32_768

    public enum Error: Swift.Error, CustomStringConvertible {
        case plaintextTooLargeForBucket(actualBytes: Int, bucketBytes: Int)
        case malformedPadding

        public var description: String {
            switch self {
                case .plaintextTooLargeForBucket(let a, let b):
                return "StrongboxPadding: plaintext \(a) bytes exceeds bucket \(b) bytes"
                case .malformedPadding:
                return "StrongboxPadding: padding marker missing or malformed"
            }
        }
    }

    /// Pad `plaintext` to exactly `bucketSize` bytes using the
    /// `0x80 || 0x00*` scheme. Throws if `plaintext.count >=
    /// bucketSize` because the marker byte itself needs at
    /// least one trailing position.
    public static func pad(_ plaintext: Data) throws -> Data {
        guard plaintext.count < bucketSize else {
            throw Error.plaintextTooLargeForBucket(
                actualBytes: plaintext.count,
                bucketBytes: bucketSize)
        }
        var padded = Data(count: bucketSize)
        padded.replaceSubrange(0..<plaintext.count, with: plaintext)
        padded[plaintext.count] = 0x80
        // Bytes after the marker are already 0x00 from
        // `Data(count:)`; no additional fill needed.
        return padded
    }

    /// Reverse of `pad`. Walks from the tail, skipping zeros,
    /// expects 0x80, returns the prefix.
    public static func unpad(_ padded: Data) throws -> Data {
        guard padded.count == bucketSize else {
            throw Error.malformedPadding
        }
        // Find the marker byte by walking from the end.
        var i = padded.count - 1
        while i >= 0 && padded[i] == 0x00 {
            i -= 1
        }
        guard i >= 0, padded[i] == 0x80 else {
            throw Error.malformedPadding
        }
        return padded.prefix(i)
    }
}
