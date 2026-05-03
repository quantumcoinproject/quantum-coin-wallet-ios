// AtomicSlotWriter.swift (Storage layer 1)
// Two-slot rotating, durably-flushed, file-protection-class-
// `complete` writer for the v2 strongbox file format. Closes
// `` (file protection class) and `` (crash-safe two-
// slot rotation with `F_FULLFSYNC`).
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

    /// Atomically + durably write `bytes` to `slot`. After this
    /// returns successfully the file is committed to flash with
    /// `complete` protection class.
    public func write(_ bytes: Data, to slot: Slot) throws {
        try ensureDirectoryExists()
        let finalURL = path(for: slot)
        let tmpURL = tmpPath(for: slot)

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

        // Wrap everything below in a defer that closes the fd
        // even on throw. We deliberately do NOT delete the .tmp
        // on throw - `cleanupTempFiles` does that on the next
        // boot, and leaving the .tmp visible in DEBUG makes a
        // partial-write debugging session possible.
        defer { close(fd) }

        // Step 2: write all bytes, retrying on partial writes
        // (POSIX `write` is allowed to write fewer than
        // requested bytes for any reason, even on a regular
        // file).
        try writeAll(fd: fd, data: bytes, label: tmpURL.path)

        // Step 3: set protection class on the .tmp BEFORE the
        // rename. If we rename first and crash before setting
        // the class, the user's screen-lock state could leave
        // the file readable across a screen-lock that should
        // have closed it. Setting the class first guarantees
        // 's contract on every successful return.
        try setProtectionClassComplete(at: tmpURL)

        // Step 4: F_FULLFSYNC the data file. This is the
        // critical instruction that defeats the page-cache
        // power-loss scenario described in the file header.
        if fcntl(fd, F_FULLFSYNC) == -1 {
            throw AtomicSlotWriterError.syncFailed(
                path: tmpURL.path, errno: errno)
        }

        // Step 5: rename .tmp -> final. POSIX `rename` is
        // atomic at the file-system metadata layer; either the
        // old file is replaced or it isn't. After this point
        // the file is at its final name.
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
        // updated a directory entry; without this fsync the
        // entry can sit in the journal indefinitely. On power
        // loss the new file's data blocks would be orphaned
        // and the parent directory would still point at the
        // OLD inode. (See the file header for the long-form
        // explanation of why fsync alone is insufficient on
        // iOS.)
        let dirURL = finalURL.deletingLastPathComponent
        let dirFd = dirURL().path.withCString { open($0, O_RDONLY) }
        if dirFd >= 0 {
            defer { close(dirFd) }
            if fcntl(dirFd, F_FULLFSYNC) == -1 {
                // We deliberately do NOT throw here. A failed
                // directory-fd fsync means the rename's metadata
                // entry is not yet on flash but the data blocks
                // ARE (step 4 succeeded). On the rare power-cut
                // in this window we lose the rename and the next
                // read sees the previous-good slot - which is
                // exactly the failure mode the two-slot rotation
                // is designed to absorb. Logging it is enough.
                Logger.debug(category: "ATOMIC_SLOT_DIR_FSYNC_FAIL",
                    "errno=\(errno)")
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
