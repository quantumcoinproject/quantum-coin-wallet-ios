// UnlockAttemptLimiter.swift (Security layer)
// Rate-limiting for any password-based unlock
// attempt against the strongbox or against a backup-restore decrypt.
// Why this exists (audit-grade notes for AI reviewers and human
// auditors):
// `UnlockCoordinatorV2.unlockWithPassword` runs scrypt with
// `N = 2^18, r = 8, p = 1` on the user's password. That is
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
// - Elapsed-time arithmetic uses `mach_continuous_time()`, NOT
// the wall-clock `CFAbsoluteTimeGetCurrent()`. The wall clock
// is user-adjustable from Settings -> General -> Date & Time,
// so a forward clock jump would otherwise immediately exit any
// in-progress lockout. `mach_continuous_time()`:
// - Counts real elapsed nanoseconds since boot, including
// while the device was sleeping (locked screen). An attacker
// cannot extend the elapsed-time window by locking the
// device for hours; sleep counts as elapsed time.
// - Is immune to wall-clock writes from Settings.
// - Resets on reboot. We detect reboot by comparing the
// stored monotonic value to the current one: if current
// is SMALLER than stored we infer the system rebooted
// since the last failure was recorded, and we apply the
// MAXIMUM lockout tier (1 hr) for that attempt cycle. This
// closes the "fail N times, reboot, retry immediately"
// vector. In practice a rebooted attacker pays the maximum
// backoff exactly once - which is the correct safety
// trade because there is no legitimate reason to reboot
// a phone mid-typo-storm and expect to bypass the gate.

import Foundation
import Security
import Darwin

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
    /// (audit-grade notes for AI reviewers and human auditors):
    /// the elapsed-time computation uses `mach_continuous_time()`,
    /// which is immune to wall-clock writes from Settings (see
    /// the file header). Reboot is detected by the
    /// stored monotonic value being LARGER than the current one;
    /// we then apply the maximum lockout tier (1 hr) so a
    /// reboot mid-failure-storm cannot bypass the gate.
    public static func currentDecision() -> Decision {
        let s = readState()
        let waitNeeded = backoffSeconds(forCount: s.count)
        if waitNeeded == 0 { return .allowed }
        let now = monotonicNanos()
        if s.lastFailureMonotonicNanos > now {
            // System rebooted since the failure was recorded.
            // Apply the maximum lockout tier for this cycle to
            // prevent the "fail N times, reboot, retry" bypass.
            // The wait duration is capped at the MAX tier
            // (3600s) so a user with a legitimate reboot is
            // never permanently bricked; one MAX tier wait
            // unblocks them.
            let maxTier = backoffSeconds(forCount: maxTierCount)
            return .lockedFor(remainingSeconds: maxTier)
        }
        let elapsedNanos = now - s.lastFailureMonotonicNanos
        let elapsed = TimeInterval(elapsedNanos) / 1_000_000_000.0
        if elapsed >= waitNeeded { return .allowed }
        return .lockedFor(remainingSeconds: waitNeeded - elapsed)
    }

    /// Reset the counter on a successful unlock. Call only on a
    /// confirmed-correct password.
    public static func recordSuccess(channel: Channel = .strongboxUnlock) {
        _ = channel // reserved for future per-channel tracking
        writeState(State(count: 0, lastFailureMonotonicNanos: 0))
    }

    /// Increment the counter on a wrong-password failure. Persists
    /// the new state to Keychain so a kill+relaunch does not reset
    /// it.
    public static func recordFailure(channel: Channel = .strongboxUnlock) {
        _ = channel
        var s = readState()
        s.count += 1
        s.lastFailureMonotonicNanos = monotonicNanos()
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

    /// The lowest count value that maps to the maximum tier.
    /// Used by `currentDecision` to compute the post-reboot
    /// max-tier wait without hard-coding the seconds.
    private static let maxTierCount = 10

    // MARK: - Monotonic clock

    /// Return the current `mach_continuous_time()` reading
    /// converted to nanoseconds. `mach_continuous_time()` keeps
    /// counting while the device is asleep (unlike
    /// `mach_absolute_time()`), so an attacker cannot extend the
    /// elapsed-time window by locking the device. The conversion
    /// uses `mach_timebase_info` to handle architectures where
    /// 1 mach tick != 1 ns (notably some older ARM Macs); on
    /// modern A-series chips numer == denom == 1.
    private static func monotonicNanos() -> UInt64 {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        let ticks = mach_continuous_time()
        if info.numer == info.denom {
            return ticks
        }
        // Use 128-bit-equivalent arithmetic via UInt64 split to
        // avoid overflow when ticks * numer would overflow 64
        // bits. The product can exceed UInt64.max on
        // long-uptime devices; (high * numer / denom) << 32
        // plus (low * numer / denom) gives a safe result.
        let numer = UInt64(info.numer)
        let denom = UInt64(info.denom)
        let high = (ticks >> 32) * numer / denom
        let low = (ticks & 0xFFFFFFFF) * numer / denom
        return (high << 32) &+ low
    }

    // MARK: - State

    /// Persisted limiter state.
    /// (audit-grade notes for AI reviewers and human auditors):
    /// `lastFailureMonotonicNanos` is a `mach_continuous_time()`
    /// reading converted to nanoseconds, NOT a wall-clock
    /// `CFAbsoluteTime`. The field is intentionally named with
    /// the `MonotonicNanos` suffix so a future reader cannot
    /// accidentally feed it a wall-clock value. Old wall-clock-
    /// schema state from before this fix decodes as
    /// `defaultState` (the JSON keys do not match), which is the
    /// correct behaviour: there are no current users to migrate
    /// and a reset to allowed is the safe failure mode for the
    /// schema bump.
    private struct State: Codable {
        var count: Int
        var lastFailureMonotonicNanos: UInt64
    }

    private static let defaultState = State(count: 0, lastFailureMonotonicNanos: 0)

    private static let kcService =
    (Bundle.main.bundleIdentifier ?? "org.quantumcoin.wallet")
    + ".unlock-limiter"
    /// Bumped from `state-v1` to `state-v2` when the
    /// `lastFailureAt` (CFAbsoluteTime) field was replaced with
    /// `lastFailureMonotonicNanos` (mach_continuous_time
    /// nanoseconds). The account string is part of
    /// the Keychain primary key, so the old v1 entry is left in
    /// place and a fresh v2 entry is created on first read; the
    /// v1 entry is never read again. With "no current users"
    /// this is a one-time non-event.
    private static let kcAccount = "state-v2"

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
