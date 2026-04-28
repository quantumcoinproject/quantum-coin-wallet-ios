//
// JsEngine.swift
//
// Port of WebViewManager.java. Owns a single `WKWebView` that hosts
// bridge.html + quantumcoin-bundle.js and brokers every call to the JS
// side. Exactly one instance per process - enforced by `shared`.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/bridge/WebViewManager.java
//

import Foundation
import WebKit

/// Callback shape used by `JsBridge` to await bridge results.
public protocol BridgeCallback: AnyObject {
    func onResult(_ json: String)
    func onError(_ message: String)
}

/// Single-process-wide WKWebView host for `bridge.html` +
/// `quantumcoin-bundle.js`.
///
/// - Initialization happens on the main thread (WKWebView requirement).
/// - `waitUntilReady` blocks a caller until `didFinish` fires for the
///   bundled `appassets://bridge.html` URL.
/// - Must never be invoked from the main thread via
///   `JsBridge.blockingCall` - use the async wrappers.
@MainActor
public final class JsEngine: NSObject {

    // MARK: - Public singleton

    public static let shared = JsEngine()

    // MARK: - JS interface

    /// Name of the `WKScriptMessageHandler` registered on the web content.
    /// Must match the handler string installed by
    /// `WKUserContentController.add(_:name:)` and referenced from the JS
    /// side as `window.webkit.messageHandlers.androidBridge.postMessage`.
    ///
    /// The JS side (`bridge.html`) calls through a shim named
    /// `window.AndroidBridge.*` - we install that shim as a
    /// `WKUserScript` at `.atDocumentStart` so legacy JS code continues
    /// to work unchanged.
    private static let interfaceName = "androidBridge"

    /// Custom scheme that resolves to bundled resources. Mirrors
    /// Android's `WebViewAssetLoader` + `https://appassets.androidplatform.net/`.
    private static let assetsScheme = "appassets"
    private static let bridgeURLString = "\(assetsScheme)://bridge.html"

    // MARK: - State

    private var webView: WKWebView!
    private let schemeHandler = AppAssetsSchemeHandler()
    private let pendingCallbacks = PendingCallbackStore()
    private let pendingPayloads = PendingPayloadStore()
    private let ready = AtomicBool()
    private let readyLatch = OneShotLatch()

    // MARK: - Init

    private override init() {
        super.init()
        createWebView()
    }

    // MARK: - Public API

    /// `true` after `bridge.html` has finished loading (and the JS SDK
    /// has registered its `bridge` global).
    public var isReady: Bool { ready.value }

    /// Block the current thread until the bridge is ready or `timeout`
    /// seconds elapse. Safe to call from any thread; internally hops to
    /// the main thread only for the `WKWebView` handshake.
    ///
    /// - Returns: `true` if the bridge became ready, `false` on timeout.
    nonisolated public func waitUntilReady(timeout: TimeInterval = 30) -> Bool {
        // readyLatch is nonisolated and Sendable; no MainActor hop needed.
        return readyLatch.await(timeout: timeout)
    }

    /// Fire-and-forget JavaScript evaluation, main-thread safe.
    /// `nonisolated` so background callers (e.g. `JsBridge.blockingCall`)
    /// can invoke without an `await`; the body hops to the main actor
    /// before touching `webView`.
    nonisolated public func evaluate(_ script: String, completion: ((Any?, Error?) -> Void)? = nil) {
        if Thread.isMainThread {
            MainActor.assumeIsolated {
                self.webView.evaluateJavaScript(script, completionHandler: completion)
            }
        } else {
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self.webView.evaluateJavaScript(script, completionHandler: completion)
                }
            }
        }
    }

    /// Register a callback under `requestId`. Returns after the callback
    /// table has accepted the entry; the caller is responsible for
    /// supplying the matching `evaluate(...)` call.
    /// `nonisolated` because `pendingCallbacks` is a Sendable lock-backed
    /// store and is safe from any thread.
    nonisolated public func registerCallback(requestId: String, callback: BridgeCallback) {
        pendingCallbacks.set(callback, for: requestId)
    }

    /// Stage a JSON payload for pull-model delivery. Bounded by
    /// `PendingPayloadStore.maxEntries` to prevent runaway growth if the
    /// JS side never pulls.
    nonisolated public func storePendingPayload(requestId: String, json: String) throws {
        try pendingPayloads.put(requestId: requestId, json: json)
    }

    /// Remove a staged payload without delivering it. Called by
    /// `JsBridge.blockingCall` on the timeout / error path so sensitive
    /// strings do not linger.
    nonisolated public func removePendingPayload(requestId: String) {
        pendingPayloads.remove(requestId)
    }

    // MARK: - Internal

    private func createWebView() {
        let config = WKWebViewConfiguration()
        // iOS 14+ replacement for the deprecated
        // `preferences.javaScriptEnabled = true`. Deployment target is
        // 15.0 (project.yml) so the older API is unreachable.
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        // mirrors WebSettings.setDomStorageEnabled(false) + MediaPlaybackRequiresUserGesture.
        config.websiteDataStore = .nonPersistent()
        config.mediaTypesRequiringUserActionForPlayback = .all
        if #available(iOS 14.0, *) {
            config.limitsNavigationsToAppBoundDomains = true
        }

        let ucc = WKUserContentController()
        ucc.add(ScriptMessageBroker(owner: self), name: Self.interfaceName)
        ucc.addUserScript(Self.makeAndroidBridgeShim())
        config.userContentController = ucc

        schemeHandler.owner = self
        config.setURLSchemeHandler(schemeHandler, forURLScheme: Self.assetsScheme)

        let wv = WKWebView(frame: .zero, configuration: config)
        wv.navigationDelegate = self
        wv.isHidden = true
        self.webView = wv

        guard let url = URL(string: Self.bridgeURLString) else {
            assertionFailure("bad bridge URL literal")
            return
        }
        wv.load(URLRequest(url: url))
    }

    /// Shim that installs `window.AndroidBridge.*` in terms of WebKit's
    /// native `postMessage` interface. Kept 1:1 with the `@JavascriptInterface`
    /// methods exposed by `WebViewManager.java` so the JS bridge code runs
    /// unchanged.
    ///
    /// Note: `isDebug()` is exposed synchronously because `bridge.html`
    /// uses it to gate `console.*` logging. On iOS we read a compile-time
    /// `#if DEBUG` via the user script so behaviour matches
    /// `BuildConfig.DEBUG` on Android.
    ///
    /// `getPendingPayload` and `onResult` / `onError` all post their
    /// payloads through the message handler and block on a generated
    /// reply id for the synchronous `getPendingPayload` case. WebKit
    /// does not support synchronous JS->native calls, so we use a
    /// short-lived `XMLHttpRequest`-free polling approach via
    /// `fetch(appassets:///bridge-payload/<id>)`. The scheme handler
    /// resolves those URLs to the staged payload.
    private static func makeAndroidBridgeShim() -> WKUserScript {
        let isDebug: String
        #if DEBUG
        isDebug = "true"
        #else
        isDebug = "false"
        #endif
        let src = """
        (function () {
            if (window.AndroidBridge) return;
            function post(name, args) {
                window.webkit.messageHandlers.\(interfaceName).postMessage({
                    m: name, args: args || []
                });
            }
            window.AndroidBridge = {
                isDebug: function () { return \(isDebug); },
                onResult: function (requestId, jsonResult) {
                    post('onResult', [String(requestId || ''), String(jsonResult || '')]);
                },
                onError: function (requestId, error) {
                    post('onError', [String(requestId || ''), String(error || '')]);
                },
                getPendingPayload: function (requestId) {
                    // Synchronous pull via XHR against the custom scheme.
                    // The URL shape is opaque to the scheme handler; we
                    // use 'appassets:///bridge-payload/<id>'.
                    try {
                        var xhr = new XMLHttpRequest();
                        xhr.open('GET', 'appassets:///bridge-payload/' + encodeURIComponent(requestId || ''), false);
                        xhr.send(null);
                        if (xhr.status === 200) return xhr.responseText;
                    } catch (e) {}
                    return '';
                }
            };
        })();
        """
        return WKUserScript(source: src, injectionTime: .atDocumentStart, forMainFrameOnly: true)
    }

    fileprivate func dispatchResult(requestId: String, json: String) {
        guard let cb = pendingCallbacks.remove(requestId) else { return }
        // Match Android: parse `{"success":true|false,"error"?,"data"?}`
        // and route to onResult/onError accordingly.
        if let data = json.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let ok = (obj["success"] as? Bool) ?? false
            if ok {
                cb.onResult(json)
            } else {
                cb.onError((obj["error"] as? String) ?? "Unknown bridge error")
            }
        } else {
            // Non-JSON payload - preserve Android fallback.
            cb.onResult(json)
        }
    }

    fileprivate func pullPayload(requestId: String) -> String? {
        return pendingPayloads.takeIfFresh(requestId)
    }
}

// MARK: - WKNavigationDelegate

extension JsEngine: WKNavigationDelegate {
    public func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        if webView.url?.absoluteString == Self.bridgeURLString {
            ready.value = true
            readyLatch.signal()
        }
    }
}

// MARK: - Script message broker

/// Receives raw `postMessage` payloads from `window.webkit` and routes
/// `onResult` / `onError` into `JsEngine`. Kept as a separate object to
/// avoid a retain cycle with `WKUserContentController`.
private final class ScriptMessageBroker: NSObject, WKScriptMessageHandler {
    weak var owner: JsEngine?

    init(owner: JsEngine) { self.owner = owner; super.init() }

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any],
              let method = body["m"] as? String,
              let args = body["args"] as? [String]
        else { return }
        guard let owner = owner else { return }
        switch method {
        case "onResult":
            guard args.count >= 2 else { return }
            MainActor.assumeIsolated {
                owner.dispatchResult(requestId: args[0], json: args[1])
            }
        case "onError":
            // Android side pipes this through `onResult` with success:false;
            // we preserve that behaviour for parity.
            guard args.count >= 2 else { return }
            let envelope = "{\"success\":false,\"error\":\(JSONEncoder.stringLiteral(args[1]))}"
            MainActor.assumeIsolated {
                owner.dispatchResult(requestId: args[0], json: envelope)
            }
        default: break
        }
    }
}

// MARK: - Scheme handler

/// Resolves `appassets://bridge.html` and `appassets://quantumcoin-bundle.js`
/// to files in the main bundle's `Resources` directory, and resolves
/// `appassets:///bridge-payload/<requestId>` to the staged JSON payload.
/// Mirrors Android's `WebViewAssetLoader` one-to-one.
private final class AppAssetsSchemeHandler: NSObject, WKURLSchemeHandler {
    weak var owner: JsEngine?

    func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
        guard let url = urlSchemeTask.request.url else {
            urlSchemeTask.didFailWithError(URLError(.badURL))
            return
        }

        if url.path.hasPrefix("/bridge-payload/") {
            // JS-side pull of a staged payload. URL shape:
            //   appassets:///bridge-payload/<requestId>
            let last = url.lastPathComponent
            let reqId = last.removingPercentEncoding ?? last
            let body = MainActor.assumeIsolated { owner?.pullPayload(requestId: reqId) ?? "" }
            respond(task: urlSchemeTask, url: url, body: Data(body.utf8), mime: "text/plain")
            return
        }

        // Bundled resource. Two URL shapes are possible because WebKit
        // resolves relative `<script src=...>` against the document URL:
        //   - `appassets://bridge.html`                          (host-only, initial load)
        //   - `appassets://bridge.html/quantumcoin-bundle.js`    (relative resolution)
        //   - `appassets:///quantumcoin-bundle.js`               (root-relative, hypothetical)
        // Prefer the last path component when present, else the host.
        let trimmed = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let filename: String
        if !trimmed.isEmpty {
            filename = url.lastPathComponent
        } else if let host = url.host, !host.isEmpty {
            filename = host
        } else {
            urlSchemeTask.didFailWithError(URLError(.badURL))
            return
        }
        guard let bundleURL = Bundle.main.url(forResource: filename, withExtension: nil) else {
            urlSchemeTask.didFailWithError(URLError(.fileDoesNotExist))
            return
        }
        do {
            let data = try Data(contentsOf: bundleURL)
            let mime: String
            if filename.hasSuffix(".html") { mime = "text/html" }
            else if filename.hasSuffix(".js") { mime = "application/javascript" }
            else { mime = "application/octet-stream" }
            respond(task: urlSchemeTask, url: url, body: data, mime: mime)
        } catch {
            urlSchemeTask.didFailWithError(error)
        }
    }

    func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {
        // Nothing to cancel; all reads are synchronous.
    }

    private func respond(task: WKURLSchemeTask, url: URL, body: Data, mime: String) {
        let resp = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Content-Type": mime,
                "Content-Length": String(body.count),
                // Needed so the synchronous XHR from the JS shim does not
                // get blocked by WebKit's CORS preflight logic.
                "Access-Control-Allow-Origin": "*"
            ]
        )!
        task.didReceive(resp)
        task.didReceive(body)
        task.didFinish()
    }
}

// MARK: - Helpers

/// Small thread-safe mutable bool. `WKWebView` is MainActor-isolated but
/// the ready flag is read from background threads as part of
/// `waitUntilReady`, which is why we need an explicit lock here.
private final class AtomicBool: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = false
    var value: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _value }
        set { lock.lock(); _value = newValue; lock.unlock() }
    }
}

/// One-shot latch used to signal bridge readiness across threads.
/// Replacement for Android's `CountDownLatch(1)`.
///
/// Uses `NSCondition` rather than `DispatchSemaphore` so a single
/// `signal()` releases EVERY pending waiter via `broadcast()`. The
/// original `DispatchSemaphore` flavour would only wake one of N
/// concurrent `waitUntilReady` callers, so a second waiter (e.g. the
/// `BlockchainNetworkManager.applyActive` Task.detached racing with
/// the AppDelegate's `loadSeedsThreadEquivalent` task) would park
/// for the full timeout even though `bridge.html` had already loaded.
private final class OneShotLatch: @unchecked Sendable {
    private let cond = NSCondition()
    private var signaled = false

    func signal() {
        cond.lock()
        if !signaled {
            signaled = true
            cond.broadcast()
        }
        cond.unlock()
    }

    func await(timeout: TimeInterval) -> Bool {
        cond.lock()
        defer { cond.unlock() }
        if signaled { return true }
        let deadline = Date(timeIntervalSinceNow: timeout)
        while !signaled {
            if !cond.wait(until: deadline) { return signaled }
        }
        return true
    }
}

/// Pending callback registry. Thread-safe.
private final class PendingCallbackStore: @unchecked Sendable {
    private let lock = NSLock()
    private var map: [String: BridgeCallback] = [:]

    func set(_ cb: BridgeCallback, for id: String) {
        lock.lock(); map[id] = cb; lock.unlock()
    }

    func remove(_ id: String) -> BridgeCallback? {
        lock.lock(); defer { lock.unlock() }
        return map.removeValue(forKey: id)
    }
}

/// Pending payload registry with size cap + TTL. Mirrors
/// `WebViewManager.pendingPayloads` and its L-02 sweeping guarantees.
private final class PendingPayloadStore: @unchecked Sendable {
    private struct Entry { let json: String; let enqueuedAt: TimeInterval }
    private let lock = NSLock()
    private var map: [String: Entry] = [:]

    static let maxEntries = 64
    private static let ttl: TimeInterval = 60

    func put(requestId: String, json: String) throws {
        lock.lock(); defer { lock.unlock() }
        sweepExpiredLocked()
        if map.count >= Self.maxEntries {
            throw JsEngineError.pendingPayloadMapFull
        }
        map[requestId] = Entry(json: json, enqueuedAt: Self.now())
    }

    func takeIfFresh(_ requestId: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard let entry = map.removeValue(forKey: requestId) else { return nil }
        if Self.now() - entry.enqueuedAt > Self.ttl { return nil }
        return entry.json
    }

    func remove(_ requestId: String) {
        lock.lock(); _ = map.removeValue(forKey: requestId); lock.unlock()
    }

    private func sweepExpiredLocked() {
        let now = Self.now()
        map = map.filter { now - $0.value.enqueuedAt <= Self.ttl }
    }

    private static func now() -> TimeInterval { CFAbsoluteTimeGetCurrent() }
}

public enum JsEngineError: Error, CustomStringConvertible {
    case pendingPayloadMapFull
    case bridgeNotReady
    case timeout
    case callFailed(String)

    public var description: String {
        switch self {
        case .pendingPayloadMapFull: return "pending payload map full; refusing to stage new entry"
        case .bridgeNotReady:        return "Bridge WebView did not become ready in time"
        case .timeout:               return "Bridge call timed out"
        case .callFailed(let m):     return "Bridge call failed: \(m)"
        }
    }
}

// MARK: - Micro JSON string helper

fileprivate extension JSONEncoder {
    /// Quick, allocation-free string literal encoder used only for the
    /// error envelope constructed in `ScriptMessageBroker`. Escapes the
    /// exact same characters that `QuantumCoinJSBridge.escapeForJs`
    /// escapes on Android.
    static func stringLiteral(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\\": out.append("\\\\")
            case "\"": out.append("\\\"")
            case "\u{0000}": out.append("\\u0000")
            case "\n": out.append("\\n")
            case "\r": out.append("\\r")
            case "\t": out.append("\\t")
            case "\u{0008}": out.append("\\b")
            case "\u{000C}": out.append("\\f")
            case "\u{2028}": out.append("\\u2028")
            case "\u{2029}": out.append("\\u2029")
            default:
                if u.value < 0x20 {
                    out.append(String(format: "\\u%04x", u.value))
                } else {
                    out.append(Character(u))
                }
            }
        }
        out.append("\"")
        return out
    }
}

// Private constant copy so the shim can reference a raw literal with
// the same name.
private let interfaceName = "androidBridge"
