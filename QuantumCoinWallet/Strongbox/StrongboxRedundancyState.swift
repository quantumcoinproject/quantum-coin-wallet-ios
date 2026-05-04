// StrongboxRedundancyState.swift (Strongbox layer)
// Process-level signal carrying user-visible "the strongbox is
// running with degraded redundancy right now" state.
// What it closes:
//   SECURITY_AUDIT_FINDINGS.md UNIFIED-D012. The historical
//   `scheduleReMirror` path used `try?` for both the read-back and
//   the write-back, so a transient I/O failure during the re-mirror
//   left the surviving slot single-redundant indefinitely with no
//   user-visible signal. A second silent corruption (Part 3 catches
//   it at write time, but for an OLDER write that pre-dates Part 3)
//   would then trigger `bothSlotsInvalid` — i.e. the user only
//   discovers the prior re-mirror failure when the second corruption
//   has already destroyed their last good copy.
// Why this shape (process-level singleton, not a published Combine
// signal):
//   The single-slot state is sticky for the rest of the app session;
//   it clears on the next successful re-mirror or on the next
//   successful `writeNewGeneration` (both of which produce a
//   redundant pair on disk). UI sites read it once at unlock-dialog
//   present time and surface a banner; reactive observation isn't
//   required because the state changes at most a handful of times
//   per session. Keeping it a tiny singleton over Combine /
//   AsyncSequence keeps the storage layer free of UI / concurrency
//   coupling.
// Tradeoffs:
//   The singleton survives across screens but resets on app
//   relaunch (new process). That's intentional — the next launch's
//   `readWinner` will re-detect the single-slot state and re-mark
//   it via `scheduleReMirror`'s retry path. We could persist this
//   to PrefConnect, but the marginal benefit is small (the user
//   sees the banner the first time around and has the chance to
//   create a fresh backup in response).
// Cross-references:
//   - `StrongboxFileCodec.scheduleReMirror` — the only writer.
//   - SECURITY_AUDIT_FINDINGS.md UNIFIED-D012.
//   - UI surfaces (`UnlockDialogViewController` etc.) read
//     `singleSlot` at present-time to decide whether to show the
//     "create a fresh backup soon" banner.

import Foundation

public final class StrongboxRedundancyState: @unchecked Sendable {

    public static let shared = StrongboxRedundancyState()

    private let _stateLock = NSLock()
    private var _singleSlot: Bool = false

    private init() {}

    /// True when the most recent observation of strongbox
    /// redundancy was "only one slot file is currently valid".
    /// Cleared by `markRedundant()` on the next successful
    /// re-mirror or `writeNewGeneration`.
    public var singleSlot: Bool {
        _stateLock.lock(); defer { _stateLock.unlock() }
        return _singleSlot
    }

    /// Mark the strongbox as running on a single valid slot.
    /// Called by `StrongboxFileCodec.scheduleReMirror` after its
    /// retry budget is exhausted. Idempotent.
    public func markSingleSlot() {
        _stateLock.lock(); defer { _stateLock.unlock() }
        _singleSlot = true
    }

    /// Clear the single-slot flag. Called by
    /// `StrongboxFileCodec.scheduleReMirror` on a successful
    /// re-mirror, and by any other code path that produces a
    /// fresh redundant pair on disk.
    public func markRedundant() {
        _stateLock.lock(); defer { _stateLock.unlock() }
        _singleSlot = false
    }
}
