//
// BundleHash_Generated.swift
//
// AUTO-GENERATED at build time by
// scripts/embed_bundle_hash.sh.
//
// DO NOT EDIT. Any local changes will be overwritten on the next
// build. To intentionally change the embedded hash, replace the
// shipping `Resources/quantumcoin-bundle.js` with the new bundle
// and let the Pre-Build script regenerate this file.
//
// The bytes below are the SHA-256 digest of the EXACT bytes shipping
// inside the app bundle at build time. `BundleIntegrity` re-hashes
// the loaded bundle at runtime and refuses to initialize the JS
// bridge if the hashes differ.
//
// swiftlint:disable all
//

import Foundation

public enum GeneratedBundleHash {
    /// SHA-256 digest of `quantumcoin-bundle.js`, computed at build
    /// time. 32 bytes.
    public static let sha256: [UInt8] = [
        0x9f, 0xb5, 0xc1, 0x7e, 0xaa, 0x5b, 0xc7, 0x19,
        0xbd, 0xd6, 0x9b, 0x06, 0x4c, 0xfd, 0xcf, 0xce,
        0x11, 0x2e, 0x05, 0x8b, 0xfb, 0x79, 0x1e, 0xfd,
        0xab, 0xab, 0xb4, 0xa9, 0x43, 0x02, 0x94, 0x32
    ]

    /// Same digest as a 64-character lowercase hex string. Used by
    /// audit-friendly logging in DEBUG builds.
    public static let sha256Hex: String = "9fb5c17eaa5bc719bdd69b064cfdcfce112e058bfb791efdababb4a943029432"
}
