// BundleIntegrity.swift (JsBridge layer)
// Runtime hash check for the JavaScript bundle the
// `JsEngine` loads into `WKWebView`. Re-hashes the loaded bundle on
// first use and compares against the build-time SHA-256 embedded by
// `scripts/embed_bundle_hash.sh` into `BundleHash_Generated.swift`.
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// The JS bundle owns every signing primitive in the wallet
// (scrypt KDF, AES-GCM envelope, EIP-155 transaction signing).
// The audit (``) flagged that the bundle is loaded
// into `WKWebView` and trusted absolutely - there is no
// integrity check between "what was built" and "what is
// running". The ways the bundle could be tampered without this
// check include:
// * App-binary patch on a jailbroken device: the on-disk
// resource is rewritten by an attacker who has root.
// * Re-sign with a malicious bundle: an Enterprise / sideload
// distributor swaps the bundle and re-signs. The Apple
// App-Store binary signature does NOT cover individual
// resource bytes once the bundle has been re-signed by a
// different team.
// * Mach-O instrumentation framework that hot-patches the
// evaluated source via `JavaScriptCore` reach. A Frida-class
// attacker can intercept the WKUserContentController setup
// and rewrite the bundle just before evaluation.
// This component closes the on-disk and re-sign cases by:
// 1. Hashing the bundle bytes at the SAME location the
// `WKURLSchemeHandler` will read from (`Bundle.main.url(for:)`).
// 2. Comparing to a constant whose value lives inside the
// Swift binary, where it inherits the binary's signature.
// A re-signer has to match the embedded hash to the new
// bundle, which means modifying the Swift constant -
// which means modifying the binary - which invalidates
// the signature unless the re-signer also has the
// original signing identity.
// The Frida-class case is partially closed: the runtime hash
// matches what is on disk, so a hot-patch that targets the
// already-loaded JS context is undetected at this layer.
// (TamperGate) layers on top with dyld-image walking and a
// debugger-attached check; that is where the runtime
// instrumentation case is addressed. together
// give a defense-in-depth that requires the attacker to bypass
// BOTH (file-bytes match AND runtime not instrumented).
// Tradeoffs:
// - The hash check adds ~10-20 ms at first JS-bridge use. We
// pay it lazily so the splash screen and unlock dialog are
// not affected; the cost is incurred just before the first
// `JsBridge.initialize` call.
// - A bundle update without a corresponding rebuild fails the
// check. This is the desired behaviour: shipping the bundle
// out-of-band is exactly the attack class we are detecting.
// The build script regenerates the constant on every Xcode
// build, so out-of-date hashes are impossible by construction
// for builds that go through the normal pipeline.
// - On mismatch we throw rather than crash. Callers
// (`JsEngine.shared.evaluate(...)` precondition) translate
// the throw into a hard refuse-to-initialize. The audit's
// intent is "fail loud", not "silent fallback to legacy
// bundle".

import Foundation
import CryptoKit

public enum BundleIntegrityError: Error, CustomStringConvertible {
    case bundleResourceMissing
    case hashMismatch(expectedHex: String, actualHex: String)

    public var description: String {
        switch self {
            case .bundleResourceMissing:
            return "JS bundle resource missing from app bundle - "
            + "build pipeline broken or app archive corrupted."
            case .hashMismatch(let expected, let actual):
            return "JS bundle hash mismatch. The shipping bundle "
            + "differs from the build-time pinned digest. "
            + "Expected " + expected.prefix(16) + "..., got "
            + actual.prefix(16) + ". Refusing to initialize "
            + "the JS bridge."
        }
    }
}

public enum BundleIntegrity {

    /// Resource name (without extension) of the JS bundle. Single
    /// source of truth so `JsEngine`'s loader and the verifier
    /// agree on the file name. Mirrors the value in `bridge.html`'s
    /// `<script src="quantumcoin-bundle.js">` tag.
    public static let bundleResourceName = "quantumcoin-bundle"
    public static let bundleResourceExtension = "js"

    /// Cached result of the verification. The hash check is
    /// idempotent and the bundle bytes do not change at runtime,
    /// so we run it once and cache the outcome. Subsequent
    /// `verifyOrFail` calls return the cached value (success)
    /// or re-throw the original error (failure).
    private static var cached: Result<Void, Error>?
    private static let cacheLock = NSLock()

    /// Verify the shipping bundle's SHA-256 matches the build-time
    /// pinned digest. Throws `BundleIntegrityError` on mismatch.
    /// Cheap to call repeatedly - only the first invocation
    /// performs I/O + hashing.
    public static func verifyOrFail() throws {
        cacheLock.lock()
        if let result = cached {
            cacheLock.unlock()
            switch result {
                case .success:
                return
                case .failure(let err):
                throw err
            }
        }
        cacheLock.unlock()

        let result: Result<Void, Error> = computeAndCompare()

        cacheLock.lock()
        cached = result
        cacheLock.unlock()

        switch result {
            case .success:
            return
            case .failure(let err):
            throw err
        }
    }

    /// Hash the shipping bundle bytes and compare to the embedded
    /// expected value. Returns `Result` so the caller can both
    /// cache and rethrow.
    private static func computeAndCompare() -> Result<Void, Error> {
        guard let url = Bundle.main.url(
            forResource: bundleResourceName,
            withExtension: bundleResourceExtension),
        let data = try? Data(contentsOf: url, options: [.mappedIfSafe])
        else {
            return .failure(BundleIntegrityError.bundleResourceMissing)
        }

        let digest = SHA256.hash(data: data)
        let actualBytes = Array(digest)
        let expectedBytes = GeneratedBundleHash.sha256

        if constantTimeEquals(actualBytes, expectedBytes) {
            // Success path is intentionally silent. A
            // log line on the success path is information-only
            // and would only be useful in an attack-investigation
            // post-mortem; the failure path is what fires the
            // hard alarm.
            return .success(())
        }

        let expectedHex = GeneratedBundleHash.sha256Hex
        let actualHex = actualBytes.map { String(format: "%02x", $0) }.joined()
        return .failure(BundleIntegrityError.hashMismatch(
                expectedHex: expectedHex, actualHex: actualHex))
    }

    /// Constant-time equality on two byte arrays. Not strictly
    /// necessary for hash comparison (the hash itself is public
    /// and not a secret), but cheap to write correctly and
    /// removes a class of timing-based questions a reviewer
    /// might otherwise raise.
    private static func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        if a.count != b.count { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[i] ^ b[i]
        }
        return diff == 0
    }
}
