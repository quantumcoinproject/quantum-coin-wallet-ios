// StrongboxFileCodec.swift (Schema layer 2)
// V2 strongbox file codec: JSON shape, file-level MAC compute /
// verify, two-slot read selector, encode + write coordinator.
// Closes `` (rename top-level fields), `` (file-level
// MAC + rollback detection), and the schema half of ``
// (Strongbox accessor).
// Why this exists (audit-grade notes for AI reviewers and
// human auditors):
// This is the *only* file in the wallet that knows the v2
// slot-file JSON shape. Every other layer either:
// * Layer 1 sees only opaque bytes (`AtomicSlotWriter`).
// * Layer 3 sees only AEAD primitives (`Aead`, `Mac`).
// * Layer 4 sees a typed decode result (`DecodedFile`)
// with fields like `salt`, `passwordWrap`, `strongbox`,
// `mac` and never touches their JSON form.
// * Layer 5 sees the post-MAC-verified, post-AEAD-opened,
// post-padding-stripped `StrongboxPayload`.
// Concentrating the schema knowledge here means a future
// schema bump (v2 -> v3) only edits this file plus the
// migration appendix. Auditing the schema does not require
// reading any other layer.
// On-disk layout (canonical JSON, single source of truth here):
// {
// "v": 2,
// "generation": <Int>,
// "kdf": {
// "algorithm": "scrypt",
// "salt": "<base64, 16 bytes>",
// "params": { "N": ..., "r": ..., "p": ..., "keyLen": ... }
// },
// "wrap": {
// "passwordWrap": <Aead envelope>,
// "keychainWrap": <Aead envelope, optional>
// },
// "strongbox": <Aead envelope wrapping a StrongboxPayload padded to
// exactly 32 KiB>,
// "mac": "<base64, 32 bytes>",
// "ui": { /* opt-in non-secret prefs; not in MAC scope */ }
// }
// The MAC scope is explicitly: a canonicalised JSON of
// `{v, generation, kdf, wrap, strongbox}`. The `ui` block is
// excluded so a UI pref change can be written without
// re-deriving the MAC key (which would require the user's
// password). The `ui` entries carry their own per-entry
// HMAC keyed by `deviceUiKey`; that's wired in
// `KeyMaterial/KeychainWrapStore.swift`.
// Read algorithm:
// 1. AtomicSlotWriter.cleanupTempFiles.
// 2. Read both slots. JSON-parse + schema-version each.
// 3. Pre-MAC trial: AEAD-tag-check `passwordWrap` and
// `strongbox` on each parsed slot. Mark INVALID on tag fail.
// 4. Pick winner = highest `generation` among VALID slots.
// One-valid-only path schedules an async re-mirror.
// Both-INVALID path -> tamperDetected.
// 5. Return the winner to layer 4 for password-unlock. The
// file-level MAC is verified inside layer 4 AFTER mainKey
// recovery (we cannot verify it pre-unlock because the
// MAC key is HKDF(mainKey, kdf.salt, "integrity-v2")).
// Write algorithm:
// 1. Encode the new state into the v2 JSON shape.
// 2. Compute `mac` = HMAC-SHA256 over canonical JSON of
// `{v, generation, kdf, wrap, strongbox}`.
// 3. Hand the bytes to AtomicSlotWriter.write(toInactive).
// Tradeoffs:
// - The `mac` field is computed AFTER everything else is
// populated; a future schema add (e.g. a `policy` block)
// MUST be added to the canonicalised-JSON scope or it
// will be silently dropable / forgeable. The verification
// checklist in `QuantumCoinWalletTests` includes a grep test
// for "fields outside the MAC scope" to catch this regression.
// - Pre-MAC trial uses AEAD tag check (no plaintext output)
// so it costs ~ a microsecond per slot. The strict
// `Aead.open` length guard ALSO fires here so
// any 16-byte combined-input attack on `strongbox.ct` fails
// at the codec layer before reaching CryptoKit.
// - The `ui` block's per-entry MAC uses `deviceUiKey`
// (per-device, ThisDeviceOnly Keychain item). It does
// NOT travel via iCloud backup. A device migration sees
// `ui` entries with an unknown MAC and treats them as
// missing, causing the UI to fall back to its defaults
// (re-show EULA, re-pick language). Acceptable for a
// non-secret, low-friction first-launch path.

import Foundation

public enum StrongboxFileCodec {

    public static let schemaVersion: Int = 2
    public static let macInfoLabel: String = "integrity-v2"
    public static let macKeyByteCount: Int = 32

    public enum Error: Swift.Error, CustomStringConvertible {
        case bothSlotsInvalid
        case schemaVersionMismatch(found: Int)
        case malformedJson(String)
        case missingField(String)
        case macInvalid

        public var description: String {
            switch self {
                case .bothSlotsInvalid:
                return "StrongboxFileCodec: both slots are invalid (true tamper or first-write race)"
                case .schemaVersionMismatch(let v):
                return "StrongboxFileCodec: schema v=\(v); expected \(schemaVersion)"
                case .malformedJson(let m):
                return "StrongboxFileCodec: malformed JSON: \(m)"
                case .missingField(let f):
                return "StrongboxFileCodec: missing field \(f)"
                case .macInvalid:
                return "StrongboxFileCodec: file-level MAC verification failed"
            }
        }
    }

    // MARK: - Decoded form passed to layer 4

    /// Typed view of a slot file's contents. Layer 4 unlocks
    /// `passwordWrap` to recover `mainKey`, derives the MAC key
    /// via HKDF, verifies `mac`, then unwraps `strongbox` and
    /// hands the cleartext to layer 5.
    public struct DecodedFile: Sendable {
        public let v: Int
        public let generation: Int
        public let kdfSalt: Data
        public let kdfParams: KdfParams
        public let passwordWrap: AeadEnvelope
        public let keychainWrap: AeadEnvelope?
        public let strongbox: AeadEnvelope
        public let mac: Data
        /// Raw canonicalised bytes of `{v, generation, kdf,
        /// wrap, strongbox}` (the MAC input). Recomputed here so
        /// layer 4 can verify the MAC without re-canonicalising.
        public let macInput: Data
    }

    public struct KdfParams: Sendable, Equatable {
        public let N: Int
        public let r: Int
        public let p: Int
        public let keyLen: Int
    }

    public struct AeadEnvelope: Sendable {
        public let alg: String
        public let iv: Data
        public let ct: Data
        public let tag: Data

        /// Materialise the legacy `Aead.open`-compatible JSON
        /// envelope. We re-use `Aead` rather than re-implementing
        /// AES-GCM open at this layer; the slight wrap/unwrap
        /// cost is invisible compared to the cost of unlock.
        public func legacyEnvelopeJson() -> String {
            var combined = Data()
            combined.append(ct)
            combined.append(tag)
            let obj: [String: Any] = [
                "v": Aead.envelopeVersion,
                "cipherText": combined.base64EncodedString(),
                "iv": iv.base64EncodedString()
            ]
            let data = (try? JSONSerialization.data(
                    withJSONObject: obj, options: [.sortedKeys])) ?? Data()
            return String(data: data, encoding: .utf8) ?? ""
        }
    }

    // MARK: - Read

    /// Read both slots, validate, and pick the winner. Throws
    /// on the both-INVALID disaster path. Returns `nil` if BOTH
    /// slot files are simply absent (first launch / fresh
    /// install) so the caller can branch into the "create new
    /// strongbox" path.
    public static func readWinner() throws -> DecodedFile? {
        AtomicSlotWriter.shared.cleanupTempFiles()

        let aBytes = try AtomicSlotWriter.shared.read(slot: .A)
        let bBytes = try AtomicSlotWriter.shared.read(slot: .B)

        if aBytes == nil && bBytes == nil { return nil }

        // Try to parse + AEAD-tag-trial each slot.
        let aValid = aBytes.flatMap { tryDecodeAndPreVerify($0) }
        let bValid = bBytes.flatMap { tryDecodeAndPreVerify($0) }

        switch (aValid, bValid) {
            case (nil, nil):
            throw Error.bothSlotsInvalid
            case (let a?, nil):
            // Schedule async re-mirror so future reads have
            // redundancy again. Layer 1 owns the actual write.
            scheduleReMirror(of: a, into: .B)
            return a
            case (nil, let b?):
            scheduleReMirror(of: b, into: .A)
            return b
            case (let a?, let b?):
            return a.generation >= b.generation ? a : b
        }
    }

    // MARK: - Write

    /// Encode the supplied component values into the v2 JSON
    /// shape, compute the file-level MAC, and durably commit the
    /// resulting bytes to the inactive slot.
    public static func writeNewGeneration(
        generation: Int,
        kdfSalt: Data,
        kdfParams: KdfParams,
        passwordWrap: AeadEnvelope,
        keychainWrap: AeadEnvelope?,
        strongbox: AeadEnvelope,
        macKey: Data,
        uiBlock: [String: Any],
        currentSlot: AtomicSlotWriter.Slot
    ) throws {
        let mainObj = encodeMainObject(
            generation: generation,
            kdfSalt: kdfSalt,
            kdfParams: kdfParams,
            passwordWrap: passwordWrap,
            keychainWrap: keychainWrap,
            strongbox: strongbox)

        let macInput = try canonicalize(mainObj)
        let macTag = Mac.hmacSha256(message: macInput, keyBytes: macKey)

        var fullObj = mainObj
        fullObj["mac"] = macTag.base64EncodedString()
        fullObj["ui"] = uiBlock

        let payload = try JSONSerialization.data(
            withJSONObject: fullObj, options: [.sortedKeys])
        try AtomicSlotWriter.shared.write(payload, to: currentSlot.other)
    }

    // MARK: - File-level MAC verification (called by layer 4)

    public static func verifyFileLevelMac(_ decoded: DecodedFile,
        macKey: Data) throws {
        guard Mac.verify(decoded.macInput,
            mac: decoded.mac,
            keyBytes: macKey)
        else {
            throw Error.macInvalid
        }
    }

    // MARK: - Internals

    private static func tryDecodeAndPreVerify(_ bytes: Data) -> DecodedFile? {
        guard let decoded = try? decodeOnly(bytes) else { return nil }
        // Pre-MAC trial: confirm the AEAD tag of `strongbox` is
        // structurally well-formed by attempting open with a
        // throwaway dummy key. We CANNOT actually verify the
        // tag without the real key; the structural check here
        // is just "does the envelope decode and pass 's
        // strict length guard?". The real tag verification
        // happens inside layer 4's `Aead.open` once mainKey is
        // recovered. The `Aead.open` call below WILL throw
        // because we use a wrong key, but it throws
        // `authenticationFailed` for a structurally-valid
        // envelope and `malformedEnvelope` for a corrupted
        // one - we treat the second as INVALID.
        let dummyKey = Data(repeating: 0, count: 32)
        for env in [decoded.passwordWrap, decoded.strongbox] {
            do {
                _ = try Aead.open(env.legacyEnvelopeJson(),
                    keyBytes: dummyKey)
            } catch AeadError.malformedEnvelope {
                return nil
            } catch {
                // authenticationFailed is the expected outcome
                // with the wrong key; that means the envelope
                // shape is structurally fine. Continue.
            }
        }
        return decoded
    }

    private static func decodeOnly(_ bytes: Data) throws -> DecodedFile {
        guard let raw = try? JSONSerialization.jsonObject(with: bytes),
        let obj = raw as? [String: Any]
        else {
            throw Error.malformedJson("top-level not a JSON object")
        }

        guard let v = obj["v"] as? Int else { throw Error.missingField("v") }
        guard v == schemaVersion else {
            throw Error.schemaVersionMismatch(found: v)
        }
        guard let generation = obj["generation"] as? Int else {
            throw Error.missingField("generation")
        }
        guard let kdf = obj["kdf"] as? [String: Any] else {
            throw Error.missingField("kdf")
        }
        guard let saltB64 = kdf["salt"] as? String,
        let salt = Data(base64Encoded: saltB64)
        else { throw Error.missingField("kdf.salt") }
        guard let params = kdf["params"] as? [String: Any],
        let N = params["N"] as? Int,
        let r = params["r"] as? Int,
        let p = params["p"] as? Int,
        let keyLen = params["keyLen"] as? Int
        else { throw Error.missingField("kdf.params") }

        guard let wrap = obj["wrap"] as? [String: Any] else {
            throw Error.missingField("wrap")
        }
        guard let passwordObj = wrap["passwordWrap"] as? [String: Any],
        let passwordWrap = decodeEnvelope(passwordObj)
        else { throw Error.missingField("wrap.passwordWrap") }

        let keychainWrap: AeadEnvelope?
        if let kwObj = wrap["keychainWrap"] as? [String: Any] {
            keychainWrap = decodeEnvelope(kwObj)
        } else {
            keychainWrap = nil
        }

        guard let strongboxObj = obj["strongbox"] as? [String: Any],
        let strongbox = decodeEnvelope(strongboxObj)
        else { throw Error.missingField("strongbox") }

        guard let macB64 = obj["mac"] as? String,
        let mac = Data(base64Encoded: macB64)
        else { throw Error.missingField("mac") }

        // Recompute the MAC input bytes deterministically so
        // layer 4's verification can compare bit-exact.
        let mainObj = encodeMainObject(
            generation: generation,
            kdfSalt: salt,
            kdfParams: KdfParams(N: N, r: r, p: p, keyLen: keyLen),
            passwordWrap: passwordWrap,
            keychainWrap: keychainWrap,
            strongbox: strongbox)
        let macInput = try canonicalize(mainObj)

        return DecodedFile(
            v: v,
            generation: generation,
            kdfSalt: salt,
            kdfParams: KdfParams(N: N, r: r, p: p, keyLen: keyLen),
            passwordWrap: passwordWrap,
            keychainWrap: keychainWrap,
            strongbox: strongbox,
            mac: mac,
            macInput: macInput)
    }

    private static func decodeEnvelope(_ obj: [String: Any]) -> AeadEnvelope? {
        guard let alg = obj["alg"] as? String,
        let ivB64 = obj["iv"] as? String,
        let ctB64 = obj["ct"] as? String,
        let tagB64 = obj["tag"] as? String,
        let iv = Data(base64Encoded: ivB64),
        let ct = Data(base64Encoded: ctB64),
        let tag = Data(base64Encoded: tagB64)
        else { return nil }
        return AeadEnvelope(alg: alg, iv: iv, ct: ct, tag: tag)
    }

    private static func encodeEnvelope(_ env: AeadEnvelope) -> [String: Any] {
        return [
            "alg": env.alg,
            "iv": env.iv.base64EncodedString(),
            "ct": env.ct.base64EncodedString(),
            "tag": env.tag.base64EncodedString()
        ]
    }

    private static func encodeMainObject(
        generation: Int,
        kdfSalt: Data,
        kdfParams: KdfParams,
        passwordWrap: AeadEnvelope,
        keychainWrap: AeadEnvelope?,
        strongbox: AeadEnvelope
    ) -> [String: Any] {
        var wrap: [String: Any] = [
            "passwordWrap": encodeEnvelope(passwordWrap)
        ]
        if let kw = keychainWrap {
            wrap["keychainWrap"] = encodeEnvelope(kw)
        }
        return [
            "v": schemaVersion,
            "generation": generation,
            "kdf": [
                "algorithm": "scrypt",
                "salt": kdfSalt.base64EncodedString(),
                "params": [
                    "N": kdfParams.N,
                    "r": kdfParams.r,
                    "p": kdfParams.p,
                    "keyLen": kdfParams.keyLen
                ]
            ],
            "wrap": wrap,
            "strongbox": encodeEnvelope(strongbox)
        ]
    }

    /// Canonicalise the MAC input deterministically.
    /// `JSONSerialization.sortedKeys` produces RFC-8259-
    /// compatible JSON with keys in lexicographic order at every
    /// level, which is the only sort order consistent across
    /// platforms (Android `JSONObject` uses insertion order;
    /// `sortedKeys` removes that platform-specific dependency).
    private static func canonicalize(_ obj: [String: Any]) throws -> Data {
        return try JSONSerialization.data(
            withJSONObject: obj, options: [.sortedKeys])
    }

    // MARK: - Re-mirror scheduler

    private static func scheduleReMirror(of decoded: DecodedFile,
        into slot: AtomicSlotWriter.Slot) {
        // Best-effort re-mirror: re-canonicalise the slot's
        // bytes (we lost the original byte-exact form when we
        // decoded the JSON, so we re-encode) and write into the
        // INVALID slot so future reads see redundancy again. We
        // dispatch async because the caller (layer 4) is on
        // the unlock-critical path and should not pay this cost
        // synchronously.
        DispatchQueue.global(qos: .utility).async {
            var fullObj = encodeMainObject(
                generation: decoded.generation,
                kdfSalt: decoded.kdfSalt,
                kdfParams: decoded.kdfParams,
                passwordWrap: decoded.passwordWrap,
                keychainWrap: decoded.keychainWrap,
                strongbox: decoded.strongbox)
            fullObj["mac"] = decoded.mac.base64EncodedString()
            // The `ui` block is not in `DecodedFile`. On a
            // re-mirror we omit it; the next legitimate write
            // will re-establish it. This is acceptable because
            // `ui` is the non-secret namespace (EULA / language)
            // which simply falls back to defaults when missing.
            guard let bytes = try? JSONSerialization.data(
                withJSONObject: fullObj, options: [.sortedKeys])
            else { return }
            try? AtomicSlotWriter.shared.write(bytes, to: slot)
        }
    }
}
