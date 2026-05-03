// StrongboxPayload.swift (Strongbox layer 5)
// Typed model of the cleartext JSON inside the encrypted v2
// `strongbox` field. Closes the schema-shape half of ``.
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// In v1, every per-wallet datum (count, has-seed flag, current
// wallet index, custom networks list, backup-enabled flag,
// ...) was a separate plaintext key in `PrefConnect`. That
// leaked the wallet count and the per-wallet metadata
// structure to anyone who could read the file (the storage-
// medium exfiltration threat profile). The earlier two-tier
// layout encrypted only *some* of these fields and left the
// per-slot wallet ciphertexts
// visible alongside, so an attacker who could read the file
// knew the wallet count from key enumeration alone.
// In v2, the entire wallet semantics live inside this single
// typed payload, AES-GCM-sealed under `mainKey` and padded to
// exactly 32 KiB before sealing ( / StrongboxPadding). The
// only thing pre-unlock observable on disk is "a strongbox file
// exists" - the count, the per-wallet flags, the network
// customisations, the backup-enabled bit are all hidden by
// construction.
// The shape below is normative: any field added to v2 wallet
// semantics MUST go here, NOT into `PrefConnect`. Every
// legacy plaintext key listed at the top of `PrefConnect` is
// forbidden in v2; this struct is the single replacement.
// Layered design:
// - This file knows about wallet semantics (addresses, custom
// networks, UI state). It does NOT know about file layout
// (slot rotation, MAC, padding) - those live in layer 1
// (`AtomicSlotWriter`) and layer 2 (`StrongboxFileCodec`).
// - This file does NOT know about cryptographic primitives.
// The raw payload bytes are produced by `JSONEncoder` and
// handed to layer 3's `Aead.seal` / `Aead.open` by layer 4
// (`KeyStore` / future `Strongbox` accessor).
// - The inner `checksum` field is defense-in-depth on top of
// the outer AEAD tag: if a partial-decrypt scenario ever
// emerged (e.g. a future codec bug that decrypts only part
// of the buffer), the checksum mismatch surfaces it before
// the wallet snapshot is rebuilt. The outer tag is the
// primary integrity guarantee; checksum is an additional
// belt over the suspenders.
// Tradeoffs:
// - All wallet-semantic fields are in one buffer, so any
// mutation rewrites the entire 32 KiB. With 's two-slot
// rotation that is two flash sectors per write; on modern
// iPhones that is ~5-10 ms and under user perception.
// - The per-wallet `encryptedSeed` field nests an AES-GCM
// envelope inside the outer AES-GCM-sealed payload. This is
// intentional: it lets a single wallet's seed be
// decrypted, used for ONE signing operation, and zeroed
// without exposing every other wallet's seed in plaintext
// memory at the same time. The outer `strongbox` AEAD tag still
// binds the entire payload, so an attacker cannot swap one
// wallet's `encryptedSeed` without invalidating the outer
// tag.
// - `customNetworks` mirrors the v1 strongbox blob's `networks`
// array. The bundled MAINNET network (loaded from
// `Resources/blockchain_networks.json`) is NOT stored here -
// it is re-prepended on every `applyDecryptedConfig` call,
// keeping the bundled resource as the canonical source for
// the default chain config.

import Foundation

public struct StrongboxPayload: Codable, Sendable, Equatable {

    /// Schema version of the payload. Bumped only when an
    /// incompatible field shape change is needed. v2 is the
    /// initial version-2 payload; there is no v1 of this file
    /// (an earlier two-tier layout used a different on-disk
    /// shape entirely and was retired before any user shipped
    /// onto the v2 codec).
    public let v: Int

    /// All wallets the user has created. Order is by `idx`
    /// ascending; that ordering is also what the UI renders.
    public let wallets: [Wallet]

    /// Index of the currently-active wallet (one of the
    /// `wallets[*].idx` values). Persisted so the home strip
    /// re-opens to the same wallet across relaunches.
    public let currentWalletIndex: Int

    /// User-added custom networks. Bundled MAINNET is NOT
    /// included; layer 5 re-prepends it whenever the network
    /// list is rendered. See file header for rationale.
    public let customNetworks: [BlockchainNetwork]

    /// Index into `(bundled || customNetworks)` of the
    /// currently-active network. 0 == bundled MAINNET.
    public let activeNetworkIndex: Int

    /// User toggle: have they opted into iCloud backup?
    public let backupEnabled: Bool

    /// User-selected iCloud Drive folder for `.wallet` exports.
    /// Empty string when the user has not selected a folder yet.
    public let cloudBackupFolderUri: String

    /// User toggle: enable advanced signing UX (raw transaction
    /// preview, custom gas fields, etc.).
    public let advancedSigning: Bool

    /// Idempotency flag for the camera-permission prompt.
    /// `true` once we have asked the user (regardless of their
    /// answer) so we never re-prompt automatically.
    public let cameraPermissionAskedOnce: Bool

    /// Defense-in-depth integrity tag. SHA-256 of the canonical
    /// JSON of every preceding field. Verified post-decrypt; on
    /// mismatch we hard-fail the unlock with a tamper-detected
    /// error rather than rebuild a corrupted snapshot.
    public let checksum: String

    public struct Wallet: Codable, Sendable, Equatable {
        public let idx: Int
        public let address: String
        /// JS-bridge AES-GCM envelope of the encrypted seed/key
        /// material. Same shape as the legacy
        /// `SECURE_WALLET_<n>` per-slot ciphertext, so a future
        /// migration of the per-wallet envelope format only
        /// touches the JS bridge - not this struct.
        public let encryptedSeed: String
        /// True when the wallet was created from a seed phrase
        /// (so a seed-reveal flow is offered). False when the
        /// wallet was imported by raw private key.
        public let hasSeed: Bool
    }
}
