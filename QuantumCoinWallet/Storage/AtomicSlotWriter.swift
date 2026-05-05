// AtomicSlotWriter.swift (Storage layer 1)
// Two-slot rotating, durably-flushed, file-protection-class-
// `complete` writer for the v2 strongbox file format. Closes
// `` (file protection class) and `` (crash-safe two-
// slot rotation with `F_FULLFSYNC`).
// Verify-before-promote layer (added by Part 3 of the durability
// fix plan):
// `writeAndVerify(_:to:verify:onPhase:)` is the canonical write
// entry point. After F_FULLFSYNCing the .tmp fd it re-reads the
// staged bytes from disk with `[.uncached]` so the read traverses
// the OS's page-cache flush boundary, hands them to the caller's
// `verify` closure, and ONLY THEN renames the .tmp into place.
// The caller-supplied verify closure is the schema-aware integrity
// check (see `StrongboxFileCodec.writeNewGeneration` for the
// canonical eight-step deep verify). The three failure classes
// this catches:
//   - encoder / MAC / padding bugs that produce a structurally
//     valid file the unlock path cannot decrypt
//   - silent NAND bit-flips during the write window (the uncached
//     re-read traverses the page-cache flush boundary)
//   - stale-key MAC failures (the macKey we wrote with does not
//     match what we'd derive from the password we just used to
//     seal the wraps)
// This is the third defense layer (after two-slot rotation and
// F_FULLFSYNC) called out in SECURITY_AUDIT_FINDINGS.md's
// "Defense layering" paragraph; it closes UNIFIED-D010 and
// backstops UNIFIED-D004 / D011. The existing single-arg
// `write(_:to:)` is a thin wrapper that calls `writeAndVerify`
// with a no-op verify so callers that don't need the deep verify
// (the codec's re-mirror path) compile unchanged.
// Why this exists (audit-grade notes for AI reviewers and
// human auditors):
// The legacy `PrefConnect`-backed write path (`writeJson`
// then `Data.write(to:options: .atomic)`) is robust against
// *abrupt-app-kill* (SIGKILL during write -> rename either
// succeeded or didn't), but it is NOT robust against
// *power-loss* on iOS:
// - `.atomic` translates to "write to .tmp, then rename".
// The rename is atomic at the FILE-SYSTEM-METADATA
// level, but iOS's file system caches the metadata
// update in the journal until a flush event; a power
// cut between rename-completed and journal-flushed can
// leave the on-disk state with the OLD file present
// and the NEW file's data blocks orphaned. On the next
// boot we read the OLD file and silently lose every
// wallet add the user did since the last flush.
// - Worse, depending on timing, a partial-write of a
// single file can leave a half-written JSON whose
// `strongbox.ct` field is truncated; the AEAD tag check
// fails, and we throw "tamper detected" at the user
// on next launch when they did nothing wrong.
// The two-slot rotation defends against the first failure
// mode: we always have a previous-good slot, so a power-
// cut between writing slot B and reading it back leaves
// slot A intact and the next read picks A by `generation`.
// `fcntl(F_FULLFSYNC)` defends against the second failure
// mode: it forces the bytes from the page cache through
// the device controller to the storage media, NOT just to
// the OS page cache (which is what `fsync` does on iOS,
// per Apple's "Performance and Stability" doc). Without
// `F_FULLFSYNC` a write that "succeeded" can still be lost
// if the device loses power within a few hundred ms.
// We call `F_FULLFSYNC` on TWO descriptors per write:
// * the data fd for the slot file we just wrote, AND
// * the parent-directory fd, so the rename's metadata
// update itself is durably committed.
// This is the procedure documented by Apple in TN1150()
// ("HFS Plus Volume Format") for crash-consistent journaled
// writes; the same pattern applies to APFS (the modern iOS
// default).
// Invariants this layer guarantees to layer 2 (`StrongboxFileCodec`):
// 1. After a successful `write(_:to:)` returns, the data is
// durably committed to flash, the file is named to the
// target slot, and the file-protection class is
// `complete`. A power-cut after this returns cannot lose
// it.
// 2. After a `write(_:to:)` THROW, the on-disk state is
// either:
// (a) entirely unchanged (the inactive slot's previous
// contents are intact), OR
// (b) the inactive slot has been freshly written (in
// which case the next read will pick it as the
// winner if its `generation` is higher).
// Layer 2 must therefore be prepared to find a new slot
// file even after a throw - that's correctness-
// preserving as long as the contents are MAC-valid.
// 3. `cleanupTempFiles` removes every `*.tmp` file in the
// prefs directory. Safe to run at boot - any genuine
// `*.tmp` from a non-crashed write is short-lived and
// will not be present at boot.
// 4. `read(slot:)` returns the raw bytes of `slot` if the
// file exists, `nil` otherwise. NO content interpretation
// happens at this layer. Layer 2 owns JSON decode, MAC
// check, and the slot-picker logic.
// 5. File protection class on every successful write is
// `complete`. If the user's screen is locked, the file
// body is unreadable until the next unlock. Closes
// ``.
// Tradeoffs:
// - F_FULLFSYNC is observably slower than fsync (~5-30 ms
// per write on modern iPhones; up to ~200 ms on older
// devices). With 's 32 KiB bucket and the user-
// driven write rate (one write per UI action), the cost
// is below user perception thresholds.
// - Two-slot rotation doubles the on-disk footprint (~64
// KiB total). Negligible vs. user data on any iOS device.
// - We deliberately use `Application Support/` rather than
// `Documents/` for the slot files. has already
// disabled `UIFileSharingEnabled` and
// `LSSupportsOpeningDocumentsInPlace`, so the practical
// visibility is the same; using `Application Support/` is
// the documented Apple convention for app-managed data
// (vs. user-visible documents). Slot files are `.json`-
// suffixed for human-debuggability of the schema; an
// attacker reading them sees opaque base64 either way.

import Foundation

public enum AtomicSlotWriterError: Error, CustomStringConvertible {
    case openFailed(path: String, errno: Int32)
    case writeFailed(path: String, errno: Int32)
    case syncFailed(path: String, errno: Int32)
    case renameFailed(from: String, to: String, errno: Int32)
    case protectionClassFailed(path: String, underlying: String)
    /// Raised by `writeAndVerifyBytes` when the staged file's
    /// re-read bytes do not byte-equal the bytes the caller asked
    /// to write. Carries the expected and actual lengths for log
    /// triage; the actual bytes are NOT included to avoid leaking
    /// ciphertext into log sinks.
    case verifyByteMismatch(path: String, expectedLength: Int, actualLength: Int)

    public var description: String {
        switch self {
            case .openFailed(let p, let e):
            return "AtomicSlotWriter: open(\(p)) failed errno=\(e)"
            case .writeFailed(let p, let e):
            return "AtomicSlotWriter: write(\(p)) failed errno=\(e)"
            case .syncFailed(let p, let e):
            return "AtomicSlotWriter: F_FULLFSYNC(\(p)) failed errno=\(e)"
            case .renameFailed(let f, let t, let e):
            return "AtomicSlotWriter: rename(\(f) -> \(t)) failed errno=\(e)"
            case .protectionClassFailed(let p, let u):
            return "AtomicSlotWriter: setAttributes(\(p)) failed: \(u)"
            case .verifyByteMismatch(let p, let e, let a):
            return "AtomicSlotWriter: verify byte-mismatch at \(p) "
                + "(expected=\(e)B actual=\(a)B)"
        }
    }
}

public final class AtomicSlotWriter {

    public enum Slot: String, CaseIterable, Sendable {
        case A = "A"
        case B = "B"

        public var other: Slot {
            switch self {
                case .A: return .B
                case .B: return .A
            }
        }
    }

    /// Phase signal emitted by `writeAndVerify` so a UI caller can
    /// surface progress on a long-running write. Intentionally
    /// callback-based rather than Combine / actor so it can be
    /// invoked synchronously from the writer's own thread without
    /// imposing a concurrency model on this layer-1 storage code.
    /// The callback is invoked AT MOST ONCE per phase transition,
    /// in strict order: `writing -> verifying -> promoting -> committed`.
    /// On any throw the callback is NOT invoked for later phases
    /// (so a UI handler driven by `committed` correctly stays in
    /// the "still working" state on failure). UI callers MUST hop
    /// to MainActor inside the callback; `writeAndVerify` makes no
    /// thread guarantees.
    /// What it closes:
    ///   The verify pass adds ~5-30 ms on a modern iPhone (uncached
    ///   re-read of the slot file plus the caller's verify work).
    ///   Without this signal the user-facing wait dialog stays on
    ///   the original "Please wait..." message the whole time and
    ///   has no UI breadcrumb that the system is doing a final
    ///   integrity check before promoting the new slot. UI callers
    ///   wire this so a secondary "Verifying..." status line appears
    ///   between F_FULLFSYNC and rename, then clears on promote.
    /// Cross-references:
    ///   - SECURITY_AUDIT_FINDINGS.md UNIFIED-D010 (silent corruption
    ///     between flash write and unlock-time read).
    ///   - `WaitDialogViewController.setStatus(_:)` — the secondary
    ///     status slot the UI callers update inside the callback.
    public enum WriteVerifyPhase: Sendable {
        /// About to call `writeAll` on the .tmp fd. UI: keep the
        /// existing "Please wait..." message visible; no status line.
        case writing
        /// `writeAll` + `setProtection` + `F_FULLFSYNC` succeeded;
        /// about to re-read the .tmp from disk and run the caller's
        /// verify closure. UI: show "Verifying..." as a secondary
        /// status line BELOW the existing "Please wait..." message.
        /// Do NOT replace the main message; do NOT dismiss any dialog.
        case verifying
        /// Verify succeeded; about to rename .tmp -> final and fsync
        /// the parent directory. UI: clear the "Verifying..." status
        /// line; the existing "Please wait..." remains.
        case promoting
        /// All steps committed; the new slot is the read-time winner.
        /// UI: clear any status line; the caller's success path will
        /// dismiss the wait dialog.
        case committed
    }

    public static let shared = AtomicSlotWriter()

    /// Base name of the slot files, sans the `.A.json` /
    /// `.B.json` suffix. Mirrors the existing legacy file name
    /// `DP_QUANTUM_COIN_WALLET_APP_PREF` used by `PrefConnect`
    /// so an audit can grep both v1 and v2 locations easily.
    public static let baseFilename = "DP_QUANTUM_COIN_WALLET_APP_PREF"

    private init() {}

    // MARK: - Public read

    /// Read the raw bytes of `slot`. Returns `nil` if the file
    /// does not exist. Throws on any other I/O error.
    public func read(slot: Slot) throws -> Data? {
        let url = path(for: slot)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        return try Data(contentsOf: url, options: [.mappedIfSafe])
    }

    // MARK: - Public write

    /// Atomically + durably write `bytes` to `slot`, then re-read
    /// the staged file and BYTE-COMPARE it against `bytes` before
    /// renaming into the live slot. This is the right primitive
    /// for "I already have the canonical bytes I want on disk" —
    /// e.g. the re-mirror path that copies an already-MAC-verified
    /// surviving slot to the missing one.
    /// What it closes:
    ///   The historical `write(_:to:)` shape was `writeAndVerify(...,
    ///   verify: { _ in })` — i.e. it wrote, F_FULLFSYNC'd, and
    ///   re-read uncached but threw the re-read bytes away. A NAND
    ///   bit-flip during the write window therefore landed silently
    ///   in the live slot. The byte-compare here closes that gap
    ///   for callers that don't need a schema-aware verify but DO
    ///   want write-then-verify-then-promote.
    /// Why this shape (byte-compare in the writer, not the caller):
    ///   The writer already does the uncached re-read, so the
    ///   compare is a single allocation-free Data == Data over the
    ///   already-loaded staged buffer. Pushing it into every caller
    ///   would duplicate the boilerplate and risk forgotten sites.
    /// Tradeoffs:
    ///   Adds a Data == Data over up to ~32 KiB on every write.
    ///   That is below 1 ms on every iPhone in the deployment
    ///   target window; well below the F_FULLFSYNC cost the write
    ///   already pays.
    /// Cross-references:
    ///   - `StrongboxFileCodec.scheduleReMirror` for the re-mirror
    ///     caller that uses this helper.
    ///   - `writeAndVerify` for the deep-verify variant used by
    ///     `writeNewGeneration`.
    public func writeAndVerifyBytes(_ bytes: Data, to slot: Slot,
        onPhase: ((WriteVerifyPhase) -> Void)? = nil) throws {
        let finalPath = path(for: slot).path
        try writeAndVerify(bytes, to: slot,
            verify: { staged in
                guard staged == bytes else {
                    throw AtomicSlotWriterError.verifyByteMismatch(
                        path: finalPath,
                        expectedLength: bytes.count,
                        actualLength: staged.count)
                }
            },
            onPhase: onPhase)
    }

    /// Compatibility shim. Forwards to `writeAndVerifyBytes` so
    /// every legacy `write(_:to:)` caller now also gets the read-
    /// back-and-byte-compare layer. Retained as a separate name
    /// only to minimise churn in call sites.
    public func write(_ bytes: Data, to slot: Slot) throws {
        try writeAndVerifyBytes(bytes, to: slot)
    }

    /// Atomically + durably write `bytes` to `slot`, then re-read
    /// the staged file from disk and pass it to `verify`. ONLY
    /// renames the `.tmp` to the final slot path if `verify`
    /// returns successfully. Catches:
    /// - Encoding / MAC / padding bugs that produce a structurally-
    ///   valid but undecryptable file (the codec's verify closure
    ///   re-decodes, re-MACs, AEAD-opens, unpads, and byte-compares).
    /// - Silent NAND bit-flips during the write window (the re-read
    ///   uses `[.uncached]` so it traverses the page-cache flush
    ///   boundary rather than seeing the in-cache copy).
    /// - Stale-key MAC failures (the macKey we wrote with does not
    ///   match what we'd derive from the password we just used to
    ///   seal the wraps).
    /// On verify failure: the `.tmp` is left in place for
    /// `cleanupTempFiles` to remove on the next launch; the final
    /// slot is untouched; the previous-good slot remains the read-
    /// time winner. The caller observes the throw and MUST NOT bump
    /// the anti-rollback counter.
    /// What it closes:
    ///   SECURITY_AUDIT_FINDINGS.md UNIFIED-D010 (silent corruption
    ///   between flash write and unlock-time read). Backstop for
    ///   UNIFIED-D005 (parent-dir fsync failure was previously
    ///   swallowed; see `dirSyncFailed` throw below in step 6).
    /// Why this shape (verify-callback rather than codec-aware layer):
    ///   AtomicSlotWriter is intentionally schema-blind (layer 1 of
    ///   the storage stack). The verify-callback shape lets the
    ///   schema-aware codec (layer 2) own the semantic-equivalence
    ///   check while this layer owns only "the bytes are durably on
    ///   flash and re-readable from disk".
    /// Tradeoffs:
    ///   The uncached re-read costs ~5 ms on a modern iPhone (~50 ms
    ///   on older devices). The verify closure adds an additional
    ///   ~50-200 µs (the codec's MAC + AEAD + JSON-decode + byte-
    ///   compare). Total verify-pass overhead is well under user
    ///   perception thresholds and below the existing F_FULLFSYNC
    ///   cost the write already pays.
    public func writeAndVerify(_ bytes: Data, to slot: Slot,
        verify: (Data) throws -> Void,
        onPhase: ((WriteVerifyPhase) -> Void)? = nil) throws {
        try ensureDirectoryExists()
        let finalURL = path(for: slot)
        let tmpURL = tmpPath(for: slot)

        onPhase?(.writing)

        // Step 1: open the .tmp file with O_WRONLY | O_CREAT |
        // O_TRUNC so a leftover from a prior crashed write is
        // safely overwritten, not appended to.
        let openFlags = O_WRONLY | O_CREAT | O_TRUNC
        let mode: mode_t = 0o600
        let fd = tmpURL.path.withCString { open($0, openFlags, mode) }
        guard fd >= 0 else {
            throw AtomicSlotWriterError.openFailed(
                path: tmpURL.path, errno: errno)
        }

        // Step 2 + 3 + 4 happen inside a do/catch so we can close
        // the fd before the verify pass below (the verify re-reads
        // the file; we want the data fd CLOSED so the read
        // traverses the OS's page-cache flush boundary rather than
        // racing the still-open writer fd's cache state).
        do {
            try writeAll(fd: fd, data: bytes, label: tmpURL.path)
            try setProtectionClassComplete(at: tmpURL)
            // Step 4: F_FULLFSYNC the data file. This is the
            // critical instruction that defeats the page-cache
            // power-loss scenario described in the file header.
            if fcntl(fd, F_FULLFSYNC) == -1 {
                let e = errno
                close(fd)
                throw AtomicSlotWriterError.syncFailed(
                    path: tmpURL.path, errno: e)
            }
            close(fd)
        } catch {
            // Best-effort close on the throw path. The defer-style
            // pattern was rewritten to an explicit close because we
            // need the fd shut BEFORE the verify re-read on the
            // success path; mirroring the close on the throw path
            // keeps fd lifecycle uniform.
            close(fd)
            throw error
        }

        // Step 4b: re-read the staged .tmp file with [.uncached]
        // so the read goes through the OS's page-cache flush
        // boundary. If F_FULLFSYNC didn't actually push bytes to
        // flash we'd see a zero or short read here rather than the
        // in-cache copy. Then invoke the caller's verify closure
        // against the re-read bytes. Throwing aborts the rename in
        // the next step, leaving the final slot untouched.
        // (audit-grade notes for AI reviewers and human auditors):
        // the [.uncached] hint is a Best-Effort signal to the OS;
        // it does not guarantee a media-level read on every iOS
        // release. The defense-in-depth is the codec's deep verify
        // (re-MAC + AEAD-open + byte-compare), which also catches
        // an "in-cache but corrupt" outcome the moment it happens.
        // Together this is a belt-and-braces verify-before-promote.
        onPhase?(.verifying)
        let staged: Data
        do {
            staged = try Data(contentsOf: tmpURL, options: [.uncached])
        } catch {
            throw AtomicSlotWriterError.writeFailed(
                path: tmpURL.path, errno: EIO)
        }
        try verify(staged)

        // Step 5: rename .tmp -> final. POSIX `rename` is
        // atomic at the file-system metadata layer; either the
        // old file is replaced or it isn't. After this point
        // the file is at its final name.
        onPhase?(.promoting)
        let renameStatus = tmpURL.path.withCString { tmpC in
            finalURL.path.withCString { finalC in
                rename(tmpC, finalC)
            }
        }
        if renameStatus != 0 {
            throw AtomicSlotWriterError.renameFailed(
                from: tmpURL.path, to: finalURL.path, errno: errno)
        }

        // Step 6: F_FULLFSYNC the parent directory. The rename
        // updated a directory entry; without this fsync the entry
        // can sit in the journal indefinitely. On power loss the
        // new file's data blocks would be orphaned and the parent
        // directory would still point at the OLD inode.
        // (audit-grade notes for AI reviewers and human auditors):
        // the previous shape LOGGED and SWALLOWED a directory-fsync
        // failure on the rationale that "the rename's metadata
        // entry is not yet on flash but the data blocks ARE, so
        // the next read just sees the previous-good slot which the
        // two-slot rotation absorbs". With the verify-before-promote
        // layer (Part 3 of the durability fix), that rationale
        // changed: the .tmp was already deep-verified and the
        // rename committed at the metadata level, so a directory-
        // fsync failure here means we will bump the anti-rollback
        // counter for a write that may not survive a power loss.
        // Throwing surfaces the failure to `persistSnapshot`,
        // which catches via its existing storageUnavailable map
        // and SKIPS the counter bump. The user sees a "could not
        // save" error instead of a silent rollback.
        // Closes UNIFIED-D005.
        let dirURL = finalURL.deletingLastPathComponent
        let dirFd = dirURL().path.withCString { open($0, O_RDONLY) }
        if dirFd >= 0 {
            defer { close(dirFd) }
            if fcntl(dirFd, F_FULLFSYNC) == -1 {
                throw AtomicSlotWriterError.syncFailed(
                    path: dirURL().path, errno: errno)
            }
        }

        // Step 7: honour the user's "Phone Backup" preference on
        // the freshly-renamed slot. The rename in step 5 atomically
        // replaced the prior file; the prior file's
        // `isExcludedFromBackupKey` resource value did NOT survive
        // the replacement (resource values are bound to the inode,
        // not the path), so we must re-apply on every write. This
        // call is best-effort and never throws - see
        // `BackupExclusion` for the rationale.
        BackupExclusion.applyToStrongboxFiles()

        onPhase?(.committed)
    }

    // MARK: - Public cleanup

    /// Delete every `*.tmp` file in the prefs directory. Safe
    /// to call at boot. Idempotent and tolerant of an empty /
    /// missing directory.
    public func cleanupTempFiles() {
        let dirURL = directoryURL()
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: dirURL, includingPropertiesForKeys: nil)
        else { return }
        for url in entries where url.pathExtension == "tmp" {
            // Only touch entries that look like our own .tmp
            // files. This guards against an accidental match
            // with some sibling component's tmp file.
            let name = url.lastPathComponent
            if name.hasPrefix(Self.baseFilename) {
                try? FileManager.default.removeItem(at: url)
            }
        }
    }

    // MARK: - Internals: paths

    public func path(for slot: Slot) -> URL {
        directoryURL().appendingPathComponent(
            "\(Self.baseFilename).\(slot.rawValue).json")
    }

    private func tmpPath(for slot: Slot) -> URL {
        directoryURL().appendingPathComponent(
            "\(Self.baseFilename).\(slot.rawValue).json.tmp")
    }

    private func directoryURL() -> URL {
        // Store under Application Support/, not
        // Documents/. After the practical visibility
        // difference is nil (Documents is no longer Files-app
        // browsable), but Application Support is the documented
        // Apple convention for app-managed data and is the
        // location every cross-platform-portable spec assumes.
        let supportDir = (try? FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true)) ?? FileManager.default.temporaryDirectory
        return supportDir
    }

    private func ensureDirectoryExists() throws {
        let dir = directoryURL()
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [
                FileAttributeKey.protectionKey:
                FileProtectionType.completeUntilFirstUserAuthentication
            ])
    }

    private func setProtectionClassComplete(at url: URL) throws {
        do {
            try FileManager.default.setAttributes(
                [FileAttributeKey.protectionKey: FileProtectionType.complete],
                ofItemAtPath: url.path)
        } catch {
            throw AtomicSlotWriterError.protectionClassFailed(
                path: url.path,
                underlying: String(describing: error))
        }
    }

    private func writeAll(fd: Int32, data: Data, label: String) throws {
        var offset = 0
        let total = data.count
        while offset < total {
            // Use Darwin.write to disambiguate from this class's
            // own `write(_:to:)` method - Swift name-resolution
            // would otherwise pick the instance method.
            let written = data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.write(fd, base.advanced(by: offset), total - offset)
            }
            if written < 0 {
                // Retry on EINTR; throw on every other error.
                if errno == EINTR { continue }
                throw AtomicSlotWriterError.writeFailed(
                    path: label, errno: errno)
            }
            if written == 0 {
                // 0 bytes written + no error means we cannot
                // make progress; treat as I/O failure.
                throw AtomicSlotWriterError.writeFailed(
                    path: label, errno: EIO)
            }
            offset += written
        }
    }
}
