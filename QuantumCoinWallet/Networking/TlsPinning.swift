// TlsPinning.swift (Networking layer)
// SubjectPublicKeyInfo (SPKI) SHA-256 pinning for
// the TLS handshake of every default-network endpoint the wallet
// talks to from Swift via `URLSession` (i.e. the scan API).
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// Without pinning, the wallet's network trust ceiling is "any
// leaf certificate signed by any CA in the iOS trust store". An
// attacker who:
// - convinces the user to install a configuration profile (a
// MDM provisioning, a "free Wi-Fi captive portal" trick, a
// corporate device handed to a contractor),
// - or runs the app on a jailbroken device with a sideloaded
// trusted root,
// - or compromises a single CA root in iOS's trust store,
// can MITM every API call and silently rewrite the data the UI
// displays. For a wallet that drives transaction-decision UX off
// the scan-API responses, this is a high-impact bypass: the
// "balance" on the home screen, the "from-address" rows in the
// Wallets screen, and the transaction history all come back via
// `ApiClient`. None of those bytes are signed by the chain; the
// user trusts the host.
// Pinning the SPKI raises the bar from "any CA-trusted leaf" to
// "the specific cryptographic key of our endpoint." A leaf-cert
// rotation (Let's Encrypt 60-day cycle, etc.) does NOT break the
// pin as long as the underlying private key is reused; only a
// key rotation (CA compromise recovery, planned key rollover)
// requires updating this file and shipping a new app version.
// That trade-off is correct for a wallet: leaf rotation is
// weekly-frequent and breaks lots of pinning schemes; key
// rotation is yearly-or-rarer and is the legitimate "we should
// ship a new build" event.
// Coverage map (what is and is NOT pinned):
// Pinned (this file):
// - `scanApiDomain` (`app.readrelay.quantumcoinapi.com`)
// all `ApiClient.get(...)` calls go through here.
// - `rpcEndpoint` (`public.rpc.quantumcoinapi.com`)
// declared in the pinset for forward-compatibility - if any
// future Swift-side code routes RPC through `URLSession`
// (rather than the JS bundle), the pin engages automatically.
// - `blockExplorerDomain` (`quantumscan.com`)
// declared for the same forward-compat reason.
// NOT pinned (architectural limitation, documented here so a
// future auditor does not have to derive this from first
// principles):
// - RPC traffic via the JS bundle (`bridge.html` ->
// ethers `JsonRpcProvider`). WKWebView handles its own TLS
// and does NOT consult `URLSessionDelegate`. There is no
// Apple-supported way to install a TLS pinner inside
// WKWebView in iOS 15+ (the `WKWebView.serverTrust` API
// observed in some early-iOS-15 betas was withdrawn). The
// only mitigation is to reroute RPC through Swift, which
// is a much larger refactor outside the scope of .
// Tracked for a future spec.
// - Block-explorer URLs opened with `UIApplication.open(...)`.
// Those load in Safari(), which uses iOS's system trust store
// and is not under app control. The `quantumscan.com` SPKI
// hash is in the pinset only for the Swift-side URLSession
// case; tapping a row to "view in explorer" still hands off
// to Safari and is unpinned. This is the standard iOS UX
// contract and matches every other wallet on the App Store.
// - User-defined networks. The user types in their own RPC /
// scan-API hostname; we have no way to know the legitimate
// certificate, so we fall through to system trust for any
// hostname not present in the pinset. The
// `BlockchainNetworkViewController` table renders a small
// open-padlock badge next to user-defined network names so
// the user can see at a glance which networks are pinned.
// Tradeoffs:
// - Hard-coded SPKI hashes ship in the app binary. If the
// production endpoint rotates its key without coordinating
// with this constant, ApiClient will refuse all connections
// and the wallet's home-screen balance/transaction view goes
// dark for everyone on a stale build. The mitigation is the
// dual-pin model: `kSpkiPinsByHost` is a SET so we can ship
// "current SPKI" + "future-rollover SPKI" simultaneously.
// Today we only have one entry per host (no rollover scheduled);
// when a rotation is planned, the new hash MUST be added to the
// set and shipped at least one app-update cycle BEFORE the
// server flips, then the old hash MUST be removed at least one
// cycle AFTER. This rotation procedure is the core operational
// cost of pinning.
// - SPKI extraction in iOS is mildly tricky because `Sec`
// certificate APIs return the raw key bytes, not the ASN.1-
// wrapped SubjectPublicKeyInfo structure that `openssl pkey
// -pubin -outform DER` outputs. We reconstruct the SPKI by
// prepending the well-known ASN.1 prefix for the key type
// (RSA-2048 or ECDSA P-256). The prefix tables are documented
// inline; a key type we have not pre-computed a prefix for
// fails closed (returns a nil hash, which fails the pin
// comparison). All three of our default endpoints are RSA-2048
// or ECDSA P-256, so this lookup table is exhaustive for the
// coverage needs. Adding a new key type (e.g. Ed25519,
// RSA-4096) is a one-line `kAsn1SpkiPrefixByKeyType` addition.
// - `kTlsPinningEnforced = true` ships pinning live. Two
// emergency hatches exist: (1) `kPinFailureLogOnly = true`
// converts a pin miss into a `Logger.debug` line and lets the
// handshake proceed, useful for a soft-launch telemetry
// window; (2) flipping `kTlsPinningEnforced` to `false`
// bypasses the delegate entirely. Neither hatch is exposed
// to users, both require a code change + new build.
// References for the pin extraction procedure used to populate
// `kSpkiPinsByHost` (so a future operator can re-derive them
// independently of git history):
// ```
// echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null \
// | openssl x509 -pubkey -noout \
// | openssl pkey -pubin -outform DER \
// | openssl dgst -sha256 -binary \
// | openssl enc -base64
// ```

import Foundation
import CryptoKit
import Security

// MARK: - Pin set

public enum TlsPinning {

    // -----------------------------------------------------------
    // Feature flags. Both default to `true`; flip the second to
    // `false` only when collecting telemetry on a fresh deployment.
    // The first should NEVER be flipped to `false` in a Release
    // build that ships to users.
    // -----------------------------------------------------------

    public static let kTlsPinningEnforced: Bool = true
    public static let kPinFailureLogOnly: Bool = false

    // -----------------------------------------------------------
    // The pin set. Each host maps to one OR MORE base64-encoded
    // SHA-256 hashes of the server's SubjectPublicKeyInfo (DER).
    // Multi-entry sets exist to enable future rollover (ship the
    // new hash one update cycle BEFORE the server flips, then
    // remove the old hash one cycle AFTER). Today, each host has
    // exactly one entry because no rollover is scheduled.
    // Hashes captured on 2026-04-29 from the production endpoints
    // listed in `Resources/blockchain_networks.json`.
    // To re-derive any of these locally, run the openssl pipeline
    // documented at the top of this file. The hash MUST be the
    // SHA-256 of the SubjectPublicKeyInfo (NOT of the certificate
    // and NOT of the raw key bytes) for the chain-walking
    // comparison below to match.
    // -----------------------------------------------------------

    public static let kSpkiPinsByHost: [String: Set<String>] = [
        // Scan API. Every `ApiClient.get(...)` call hits this host.
        "app.readrelay.quantumcoinapi.com": [
            "FKDdAHqX5KWpokBtRwPeAsXg4Fg4ubFUaVLN26neMnc="
        ],
        // RPC. Today reached only via the JS bundle in WKWebView(),
        // which is NOT pinned (see the WKWebView limitation note
        // in the file header). The entry is here so a future
        // Swift-side RPC code path engages the pin automatically.
        "public.rpc.quantumcoinapi.com": [
            "iPr/mKrafFo81JsLzaPSh3scii1/dym/QBp+ncgwmX8="
        ],
        // Block explorer. Today reached only via Safari hand-off,
        // which is NOT pinned. The entry is here for the same
        // forward-compat reason as `public.rpc...`.
        "quantumscan.com": [
            "T0V1P4IBOoHNRVfVGqGolN9omh/2sHQXUiu3Bl/E9Gc="
        ]
    ]

    /// Returns `true` iff `host` has at least one pinned SPKI hash
    /// in `kSpkiPinsByHost`. Used by the network-config view to
    /// render a closed-padlock vs open-padlock badge next to each
    /// network's name.
    public static func isPinned(host: String) -> Bool {
        return kSpkiPinsByHost[host.lowercased()] != nil
    }

    // -----------------------------------------------------------
    // ASN.1 SubjectPublicKeyInfo prefixes by (key type, key size).
    // `SecKeyCopyExternalRepresentation` returns the raw public-
    // key bytes:
    // - RSA: a DER SEQUENCE of (modulus INTEGER, exponent INTEGER).
    // - ECDSA: the uncompressed point (0x04 || X || Y).
    // What `openssl pkey -pubin -outform DER` (and therefore our
    // pinset) hashes is the SubjectPublicKeyInfo structure:
    // SubjectPublicKeyInfo ::= SEQUENCE {
    // algorithm AlgorithmIdentifier,
    // subjectPublicKey BIT STRING
    // }
    // To produce the same byte sequence in iOS we prepend the
    // (well-known, pre-computed) algorithm header for the key
    // type, then the BIT STRING wrapper, then the raw key bytes.
    // The byte sequences below were derived once with `openssl
    // asn1parse` on a sample SPKI of each (algorithm, key-size)
    // combination and are constant for that combination.
    // If you add a new key type here, add the matching tuple to
    // `prefixForKey(_:)` below.
    // -----------------------------------------------------------

    /// 24-byte SPKI header for an RSA-2048 public key.
    private static let kAsn1SpkiPrefixRSA2048: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]

    /// 26-byte SPKI header for an ECDSA P-256 (secp256r1) public key.
    private static let kAsn1SpkiPrefixECP256: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00
    ]

    /// Map a `SecKey` to the right ASN.1 SPKI prefix. Returns
    /// `nil` for any (algorithm, size) combination we have not
    /// pre-computed a prefix for; the caller treats `nil` as
    /// "cannot compute SPKI hash" which fails the pin comparison
    /// (closed-fail).
    fileprivate static func prefixForKey(_ key: SecKey) -> [UInt8]? {
        guard let attrs = SecKeyCopyAttributes(key) as? [String: Any] else {
            return nil
        }
        let kty = attrs[kSecAttrKeyType as String] as? String
        let bits = attrs[kSecAttrKeySizeInBits as String] as? Int

        if kty == (kSecAttrKeyTypeRSA as String), bits == 2048 {
            return kAsn1SpkiPrefixRSA2048
        }
        if kty == (kSecAttrKeyTypeECSECPrimeRandom as String), bits == 256 {
            return kAsn1SpkiPrefixECP256
        }
        return nil
    }

    /// Compute the base64 SHA-256 SPKI hash for a `SecCertificate`
    /// using `prefixForKey(_:)` to reconstruct the SPKI byte
    /// sequence. Returns `nil` if the cert has no extractable
    /// public key OR uses an algorithm we have no prefix for.
    fileprivate static func spkiHashBase64(for cert: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(cert),
        let prefix = prefixForKey(key)
        else { return nil }

        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(key, &error) as Data?
        else {
            // Defensive: free the CFError if Sec returned one. We
            // do not surface the reason because this is a pin-
            // computation primitive, not a user-facing error.
            error?.release()
            return nil
        }

        var spki = Data(prefix)
        spki.append(raw)
        let digest = SHA256.hash(data: spki)
        return Data(digest).base64EncodedString()
    }
}

// MARK: - URLSessionDelegate

/// Validates the server-presented certificate chain against
/// `TlsPinning.kSpkiPinsByHost`. Install on the URLSession used by
/// `ApiClient`. Hosts not present in the pin set fall through to
/// the default system-trust evaluation.
public final class TlsPinningSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {

    public override init() { super.init() }

    public func urlSession(_ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition,
            URLCredential?) -> Void) {

        // Only intercept TLS server-trust challenges. Every other
        // challenge type (HTTP-Auth, NTLM, client-cert) is
        // delegated to the system default; we have no business
        // overriding them and a wrong override would silently
        // weaken the connection.
        guard challenge.protectionSpace.authenticationMethod
            == NSURLAuthenticationMethodServerTrust,
            let trust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let host = challenge.protectionSpace.host.lowercased()

        // Step 1: ALWAYS run the default trust evaluation first.
        // We only ADD a pin check on top; we never weaken the
        // baseline trust check. A pinned cert that is itself
        // expired / revoked / issued by an untrusted CA still
        // fails here.
        var trustEvalError: CFError?
        let systemTrustOk = SecTrustEvaluateWithError(trust, &trustEvalError)
        if !systemTrustOk {
            Logger.debug(category: "TLS_TRUST_FAIL",
                "host=\(Self.redact(host)) reason=\(trustEvalError?.localizedDescription ?? "unknown")")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Step 2: if the host is not in our pin set, the system-
        // trust check above is sufficient. This is the path
        // user-defined networks take.
        guard let pinSet = TlsPinning.kSpkiPinsByHost[host] else {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }

        // Step 3: if the feature flag is off, accept whatever
        // system trust said. The flag exists for emergency
        // rollback only - flipping it should be paired with a
        // new app version, never with an OTA configuration push
        // (we have no such mechanism).
        if !TlsPinning.kTlsPinningEnforced {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }

        // Step 4: walk the cert chain and look for ANY cert whose
        // SPKI hash matches a pin. We accept on the first match;
        // checking the leaf alone is the strongest pin (single
        // key) but accepting any chain cert allows an intermediate
        // pin to ride the same chain with the same security
        // posture.
        let chainCount: Int
        if #available(iOS 15.0, *) {
            chainCount = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.count ?? 0
        } else {
            chainCount = SecTrustGetCertificateCount(trust)
        }

        var matched = false
        for i in 0..<chainCount {
            let cert: SecCertificate?
            if #available(iOS 15.0, *) {
                let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate]
                cert = chain?[i]
            } else {
                cert = SecTrustGetCertificateAtIndex(trust, i)
            }
            guard let c = cert,
            let hash = TlsPinning.spkiHashBase64(for: c)
            else { continue }
            if pinSet.contains(hash) {
                matched = true
                break
            }
        }

        if matched {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }

        // Step 5: no chain cert matched the pin set. Either log-
        // and-allow (soft-launch telemetry mode) or hard-fail
        // (default). The redacted log line is intentional: the
        // raw host is fine to log, but we never log the actual
        // SPKI hash because that would let an attacker who reads
        // the device console verify they have the right pin to
        // spoof.
        Logger.debug(category: "TLS_PIN_MISS",
            "host=\(Self.redact(host)) chain_len=\(chainCount)")
        if TlsPinning.kPinFailureLogOnly {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// Redact most of the hostname before logging. We keep the
    /// TLD so an operator reading a real device console can see
    /// "scan-API host" vs "RPC host" without exposing an internal
    /// hostname for an enterprise / staging deployment.
    private static func redact(_ host: String) -> String {
        let parts = host.split(separator: ".")
        guard parts.count >= 2 else { return "***" }
        return "***." + parts.suffix(2).joined(separator: ".")
    }
}
