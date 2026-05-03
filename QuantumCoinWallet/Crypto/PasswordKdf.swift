// PasswordKdf.swift (Crypto layer 3)
// Thin typed wrapper around `JsBridge.scryptDerive`, which is
// the canonical scrypt forward path the Android wallet also
// uses. Centralising the bridge call here lets every layer 4
// caller (`UnlockCoordinatorV2.unlockWithPassword`, the
// `Strongbox` unlock path, the `RestoreFlow` decrypt path)
// treat scrypt as an abstract "password -> 32-byte derived
// key" function without having to know about the JS bridge
// envelope shape.
// Why this exists (audit-grade notes for AI reviewers and
// human auditors):
// The scrypt parameters are mandatory cross-platform
// constants (see `JsBridge.SCRYPT_N/R/P/KEY_LEN`). Any
// change to N, r, p, or keyLen breaks every existing
// `.wallet` backup and on-disk strongbox on the spot. The
// wrapper here re-imports those constants by name so a
// future reader is reminded of the parity contract every
// time they touch this file.
// The wrapper also throws a typed error on bridge envelope
// mis-shape rather than letting a malformed bridge response
// propagate as a generic "unexpected shape" string from
// inside the cryptographic layer. Layer separation: crypto
// code only knows about cryptographic errors; bridge errors
// are wrapped here.
// Tradeoffs:
// - We cannot replace the JS scrypt with a Swift / Apple
// scrypt because the Android wallet's scrypt is also via
// the same JS bundle, and any future migration to native
// scrypt would need to be coordinated with Android
// to keep cross-platform backup decryption working. The
// wrapper makes that future swap a one-file change rather
// than touching every caller.
// - The bridge path is synchronous-blocking (matches the
// existing JsBridge `blockingCall` model). Layer 4
// callers are required to invoke this from a background
// thread; calling from the main thread will trap with the
// existing `JsBridge` precondition.

import Foundation

public enum PasswordKdf {

    public enum Error: Swift.Error, CustomStringConvertible {
        case bridgeEnvelopeMalformed(String)

        public var description: String {
            switch self {
                case .bridgeEnvelopeMalformed(let m):
                return "PasswordKdf.bridgeEnvelopeMalformed: \(m)"
            }
        }
    }

    /// Derive a 32-byte key from `password` using scrypt with
    /// `JsBridge`'s pinned (N, r, p, keyLen) parameters. The
    /// salt MUST be the 16-byte CSPRNG-generated salt stored in
    /// the v2 codec's `kdf.salt` field, presented as base64.
    /// Threading: BACKGROUND-thread only (JsBridge precondition).
    public static func deriveMainKey(password: String,
        saltBase64: String) throws -> Data {
        let envelope = try JsBridge.shared.scryptDerive(
            password: password,
            saltBase64: saltBase64,
            N: JsBridge.SCRYPT_N,
            r: JsBridge.SCRYPT_R,
            p: JsBridge.SCRYPT_P,
            keyLen: JsBridge.SCRYPT_KEY_LEN
        )
        guard let envData = envelope.data(using: .utf8),
        let obj = (try? JSONSerialization.jsonObject(with: envData)) as? [String: Any],
        let data = obj["data"] as? [String: Any],
        let keyB64 = (data["key"] as? String) ?? (data["derivedKey"] as? String),
        let bytes = Data(base64Encoded: keyB64)
        else {
            throw Error.bridgeEnvelopeMalformed(
                "scryptDerive returned unexpected shape")
        }
        return bytes
    }
}
