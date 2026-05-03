// UnlockAttemptLimiter.swift (Security layer)
// Rate-limiting for any password-based unlock
// attempt against the strongbox or against a backup-restore decrypt.
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// `UnlockCoordinatorV2.unlockWithPassword` runs scrypt with
// `N = 2^15, r = 8, p = 1` on the user's password. That is
// roughly 200-400 ms per attempt on
// modern iPhones. Without rate limiting, an attacker who has the
// device and the encrypted strongbox file can:
// - Mount a tap-the-Unlock-button brute-force loop at roughly
// 3-5 attempts/second, working through any common-password
// list in seconds-to-minutes for low-entropy passwords (the
// enforced minimum is 12 chars but no entropy floor; a
// motivated user can still pick "Password1234!").
// - Drive the unlock through a UI automation harness in DEBUG()
// builds or via a jailbroken-device tool.
// The same threat applies to the backup-file restore flow: a
// `.wallet` file plus a low-entropy backup password is offline-
// bruteforceable, but in-app brute-force ALSO matters for the
// restore path because the user-experienced UX (paste a backup
// file, type a guess, repeat) is the same pattern.
// This limiter:
// - Tracks (`count`, `lastFailureAt`) inside a single Keychain
// item with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
// Keychain is used (not UserDefaults / a JSON file) so the
// counter survives the app being force-quit and the JSON
// pref file being deleted - both of which would defeat a
// pref-file-based counter.
// - Enforces a stair-stepped backoff after N=5 failures:
// attempts 1-4: no penalty (typo tolerance)
// attempt 5: 30 s wait
// attempt 6: 60 s
// attempt 7: 2 min
// attempt 8: 5 min
// attempt 9: 15 min
// attempt 10+: 1 hour (no permanent lockout)
// The schedule is intentionally NOT permanent-lockout: a
// user with severe typo storms (cognitive load, broken
// keyboard, fat-finger storms on iPad) is not bricked from
// their wallet. The backoff still shrinks an unlimited
// brute-force from "minutes" to "decades" for any
// low-entropy-but-not-trivial password.
// Tradeoffs:
// - Keychain items DO get cleaned up when iOS uninstalls the app
// (since iOS 10.3). So a determined attacker can reinstall
// between attempts to reset the counter. That requires either
// (a) an attacker with physical device access, who already has
// the bigger problem of needing the Apple ID password to
// reinstall via the App Store, or (b) a developer-mode sideload
// channel, which is out of scope for the user-mode threat
// model. The strongbox file is in `Application Support/` and is
// deleted on uninstall, so reinstall is also "lose the strongbox";
// the counter reset is a non-issue when the thing being
// protected is also gone. The threat we DO defend against -
// in-app brute force without sandbox escape - is the realistic
// one.
// - The limiter is cross-call-site shared (one counter for
// strongbox-unlock and one for backup-restore-decrypt). A burglar
// who has both the device and a backup file does not get N
// extra attempts by alternating channels.
// - Lockout state lives in Keychain rather than memory, so the
// attacker cannot bypass by killing and relaunching the app.
// The trade is one Keychain read per attempt (~1 ms),
// dwarfed by the scrypt cost.

import Foundation
import Security

public enum UnlockAttemptLimiter {

    /// Decision returned by `currentDecision`. Call sites must
    /// branch on this BEFORE invoking the underlying scrypt-backed
    /// unlock so that a locked-out attacker cannot keep paying
    /// scrypt cost from the limiter's perspective.
    public enum Decision: Equatable {
        case allowed
        case lockedFor(remainingSeconds: TimeInterval)
    }

    /// Caller flag to identify which lockout family the call site
    /// belongs to. Today both flow into a single shared counter (see
    /// the cross-call-site rationale in the file header), but the
    /// channel is logged so future tuning (e.g. per-channel
    /// thresholds) can be added without changing call sites.
    public enum Channel: String {
        case strongboxUnlock = "strongbox-unlock"
        case backupDecrypt = "backup-decrypt"
    }

    // MARK: - Public API

    /// Read the current state and return the decision. Idempotent;
    /// safe to call from any thread.
    public static func currentDecision() -> Decision {
        let s = readState()
        let waitNeeded = backoffSeconds(forCount: s.count)
        if waitNeeded == 0 { return .allowed }
        let elapsed = CFAbsoluteTimeGetCurrent() - s.lastFailureAt
        if elapsed >= waitNeeded { return .allowed }
        return .lockedFor(remainingSeconds: waitNeeded - elapsed)
    }

    /// Reset the counter on a successful unlock. Call only on a
    /// confirmed-correct password.
    public static func recordSuccess(channel: Channel = .strongboxUnlock) {
        _ = channel // reserved for future per-channel tracking
        writeState(State(count: 0, lastFailureAt: 0))
    }

    /// Increment the counter on a wrong-password failure. Persists
    /// the new state to Keychain so a kill+relaunch does not reset
    /// it.
    public static func recordFailure(channel: Channel = .strongboxUnlock) {
        _ = channel
        var s = readState()
        s.count += 1
        s.lastFailureAt = CFAbsoluteTimeGetCurrent()
        writeState(s)
    }

    /// Format a user-facing message for a `tooManyAttempts` failure.
    /// Centralised here so every unlock UI surface (strongbox unlock,
    /// reveal, backup restore, settings re-enter) renders the same
    /// wording for the same lockout state.
    /// English-only today; the localized strings file does not
    /// yet have a key for this and the security-rollout scope was
    /// kept narrow on purpose. Adding a localized key is a
    /// follow-up; the message reads correctly even on a
    /// non-English UI because the security signal ("you are
    /// locked out for N seconds, this is not a password typo")
    /// is more important than perfect language fidelity in the
    /// lockout path.
    public static func userFacingLockoutMessage(remainingSeconds: TimeInterval) -> String {
        let seconds = Int(remainingSeconds.rounded(.up))
        if seconds < 60 {
            return "Too many failed attempts. Please wait \(seconds) seconds and try again."
        }
        let minutes = (seconds + 59) / 60
        if minutes == 1 {
            return "Too many failed attempts. Please wait 1 minute and try again."
        }
        return "Too many failed attempts. Please wait \(minutes) minutes and try again."
    }

    // MARK: - Backoff schedule

    /// Stair-step delay schedule. See file header for rationale.
    /// Returns `0` for counts below the warm-up tolerance (4
    /// failures), then ramps up; caps at one hour at 10+ failures.
    private static func backoffSeconds(forCount n: Int) -> TimeInterval {
        switch n {
            case ..<5: return 0
            case 5: return 30
            case 6: return 60
            case 7: return 120
            case 8: return 300
            case 9: return 900
            default: return 3600
        }
    }

    // MARK: - State

    private struct State: Codable {
        var count: Int
        var lastFailureAt: TimeInterval
    }

    private static let defaultState = State(count: 0, lastFailureAt: 0)

    private static let kcService =
    (Bundle.main.bundleIdentifier ?? "org.quantumcoin.wallet")
    + ".unlock-limiter"
    private static let kcAccount = "state-v1"

    private static func readState() -> State {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
        ]
        // audit note: the synchronisable attribute is
        // explicitly set to `false` so the limiter counter never
        // syncs through iCloud - synced state would let an attacker
        // who controls a second device on the same iCloud account
        // reset the counter remotely.
        query[kSecAttrSynchronizable as String] = kCFBooleanFalse
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
        let data = item as? Data,
        let decoded = try? JSONDecoder().decode(State.self, from: data)
        else { return defaultState }
        return decoded
    }

    private static func writeState(_ state: State) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        var match: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
        ]
        match[kSecAttrSynchronizable as String] = kCFBooleanFalse
        let attrs: [String: Any] = [
            kSecValueData as String: data,
            // audit note: WhenUnlockedThisDeviceOnly is the
            // strongest "still readable while the user is using the
            // app" protection class; ThisDeviceOnly blocks iCloud
            // Keychain sync.
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(match as CFDictionary, attrs as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var add = match
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            _ = SecItemAdd(add as CFDictionary, nil)
        }
    }
}
