//
// CloudBackupManager.swift
//
// Port of `CloudBackupManager.java`. Handles:
//   - File backup via `UIDocumentPickerViewController(forExporting:)`.
//   - Cloud backup via `UIDocumentPickerViewController(forOpening: [.folder])`,
//     bookmarked under `CLOUD_BACKUP_FOLDER_URI_KEY` so subsequent
//     writes do not re-prompt.
//   - Restore enumeration over the cloud folder.
//   - Filename format: `UTC--{yyyy-MM-dd'T'HH-mm-ss.SSS'Z'}--{address}.wallet`.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/backup/CloudBackupManager.java
//

import UIKit
import UniformTypeIdentifiers

public final class CloudBackupManager: NSObject {

    public static let shared = CloudBackupManager()

    public static let fileExtension = "wallet"
    public static let fileMime = "application/octet-stream"

    private weak var folderPickerHost: UIViewController?
    private var folderPickerCompletion: ((Bool) -> Void)?
    private weak var restorePickerHost: UIViewController?
    private var restorePickerCompletion: (([URL]) -> Void)?

    /// True while a `UIDocumentPickerViewController(forExporting:)` is on
    /// screen. The shared `UIDocumentPickerDelegate` callbacks must
    /// branch on this flag *before* the folder-picker handling so an
    /// export pick does not get mis-routed into `persistBookmark` (which
    /// would silently overwrite the cloud-folder bookmark with the
    /// just-saved file's URL) and so we can show the success toast.
    private var exportPickerActive: Bool = false

    /// `WaitDialogViewController` shown the instant the user taps a
    /// backup / restore button so the brief lag while iOS spins up the
    /// `UIDocumentPickerViewController` (and, for cloud folders, scans
    /// iCloud Drive) is not invisible. The picker is presented on top
    /// of this dialog; the delegate methods below dismiss the dialog
    /// after the picker tears down.
    private var pickerLoadingDialog: WaitDialogViewController?

    private override init() { super.init() }

    // MARK: - Filename

    public static func buildFilename(address: String) -> String {
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd'T'HH-mm-ss.SSS'Z'"
        df.timeZone = TimeZone(identifier: "UTC")
        let ts = df.string(from: Date())
        let hex = Self.stripHexPrefix(address)
        return "UTC--\(ts)--\(hex).\(fileExtension)"
    }

    private static func stripHexPrefix(_ s: String) -> String {
        s.hasPrefix("0x") ? String(s.dropFirst(2)) : s
    }

    /// Android `extractAddressFromEncryptedJson` normalization.
    public static func extractAddress(fromEncryptedJson json: String) -> String? {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        if let a = obj["address"] as? String {
            return a.hasPrefix("0x") ? a : "0x" + a
        }
        return nil
    }

    // MARK: - File export (one-shot)

    public func exportWalletFile(address: String, walletJson: String, from vc: UIViewController) {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(Self.buildFilename(address: address))
        do {
            try Data(walletJson.utf8).write(to: tmp, options: [.atomic])
        } catch {
            Toast.showError(Localization.shared.getBackupFailedByLangValues())
            return
        }
        let picker = UIDocumentPickerViewController(forExporting: [tmp])
        // Wire the delegate so we hear about save / cancel and can show
        // the completion toast. Without this the picker dismisses
        // silently and any success path is invisible to the user.
        picker.delegate = self
        exportPickerActive = true
        presentPicker(picker, from: vc)
    }

    // MARK: - Folder picker (persisted bookmark)

    public func presentFolderPicker(from vc: UIViewController,
                                    completion: @escaping (Bool) -> Void) {
        folderPickerHost = vc
        folderPickerCompletion = completion
        // iOS analog of Android's `Intent.ACTION_OPEN_DOCUMENT_TREE`.
        // We can't relabel the system "Open" button (Apple's HIG), but
        // we can make the picker land somewhere familiar (the user's
        // Documents directory; iCloud Drive is one tap away from the
        // sidebar) and surface file extensions so the user can confirm
        // they're inside a real folder rather than picking a file.
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.folder])
        picker.allowsMultipleSelection = false
        picker.shouldShowFileExtensions = true
        // Prefer iCloud Drive's well-known on-device root so users land
        // straight in their iCloud folder; fall back to the app's
        // Documents directory when iCloud is not signed in (e.g. on
        // Simulator or new devices). UIKit silently ignores an
        // unreachable directoryURL, so the existence check is purely
        // to avoid a no-op assignment.
        let fm = FileManager.default
        let iCloud = URL(
            fileURLWithPath: "/var/mobile/Library/Mobile Documents/com~apple~CloudDocs",
            isDirectory: true)
        if fm.fileExists(atPath: iCloud.path) {
            picker.directoryURL = iCloud
        } else if let docs = try? fm.url(
            for: .documentDirectory, in: .userDomainMask,
            appropriateFor: nil, create: false) {
            picker.directoryURL = docs
        }
        picker.delegate = self
        presentPicker(picker, from: vc)
    }

    /// Write `walletJson` into the user's cloud-folder bookmark. Returns
    /// the destination URL on success so the caller can substitute the
    /// `[FOLDER]/[FILENAME]` placeholders in the success toast (the
    /// same template used by the file-export delegate path); returns
    /// `nil` and shows an error toast on failure.
    @discardableResult
    public func writeWalletFile(address: String, walletJson: String) -> URL? {
        guard let folderURL = resolveBookmark() else {
            Toast.showError(Localization.shared.getBackupFailedByLangValues())
            return nil
        }
        let ok = folderURL.startAccessingSecurityScopedResource()
        defer { if ok { folderURL.stopAccessingSecurityScopedResource() } }
        let file = folderURL.appendingPathComponent(Self.buildFilename(address: address))
        do {
            try Data(walletJson.utf8).write(to: file, options: [.atomic])
            return file
        } catch {
            Toast.showError(Localization.shared.getBackupFailedByLangValues())
            return nil
        }
    }

    public func listWalletFiles() -> [URL] {
        guard let folderURL = resolveBookmark() else { return [] }
        let ok = folderURL.startAccessingSecurityScopedResource()
        defer { if ok { folderURL.stopAccessingSecurityScopedResource() } }
        guard let files = try? FileManager.default.contentsOfDirectory(
                at: folderURL, includingPropertiesForKeys: nil) else { return [] }
        return files.filter { $0.pathExtension.lowercased() == Self.fileExtension }
    }

    public func presentRestorePicker(from vc: UIViewController,
                                     completion: @escaping ([URL]) -> Void) {
        restorePickerHost = vc
        restorePickerCompletion = completion
        let types: [UTType] = [
            UTType(filenameExtension: "wallet") ?? .data,
            .data
        ]
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: types)
        picker.allowsMultipleSelection = true
        picker.delegate = self
        presentPicker(picker, from: vc)
    }

    // MARK: - Picker presentation with loader

    /// Show a `WaitDialogViewController` immediately on `host`, then
    /// present `picker` on top once the wait dialog finishes its
    /// presentation animation. `UIDocumentPickerViewController(forOpening:
    /// [.folder])` and the export / restore pickers all take a
    /// noticeable beat to spin up (especially when iCloud Drive is
    /// being scanned), and the user previously saw nothing at all
    /// during that gap. The wait dialog stays parked underneath the
    /// picker for the duration; the `UIDocumentPickerDelegate` callbacks
    /// dismiss it after the picker tears down so the host VC is
    /// restored to a clean state.
    private func presentPicker(_ picker: UIDocumentPickerViewController,
                               from host: UIViewController) {
        let wait = WaitDialogViewController(
            message: Localization.shared.getWaitOpeningPickerByLangValues())
        pickerLoadingDialog = wait
        host.present(wait, animated: true) { [weak wait] in
            guard let wait = wait else { return }
            wait.present(picker, animated: true)
        }
    }

    /// Tear down the loading wait dialog after the picker dismisses.
    /// `animated: false` because the picker has already played its own
    /// dismissal animation; animating the wait dialog out would briefly
    /// re-expose its scrim and look like a flash.
    private func dismissPickerLoadingDialog() {
        guard let wait = pickerLoadingDialog else { return }
        pickerLoadingDialog = nil
        wait.dismiss(animated: false)
    }

    // MARK: - Bookmark persistence

    private func resolveBookmark() -> URL? {
        let b64 = PrefConnect.shared.readString(PrefKeys.CLOUD_BACKUP_FOLDER_URI_KEY)
        guard !b64.isEmpty, let data = Data(base64Encoded: b64) else { return nil }
        var stale = false
        let url = try? URL(resolvingBookmarkData: data,
                           options: [],
                           relativeTo: nil,
                           bookmarkDataIsStale: &stale)
        if stale { return nil }
        return url
    }

    private func persistBookmark(_ url: URL) {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? url.bookmarkData(options: [],
                                               includingResourceValuesForKeys: nil,
                                               relativeTo: nil) else { return }
        PrefConnect.shared.writeString(PrefKeys.CLOUD_BACKUP_FOLDER_URI_KEY,
                                        data.base64EncodedString())
    }
}

extension CloudBackupManager: UIDocumentPickerDelegate {

    public func documentPicker(_ controller: UIDocumentPickerViewController,
                               didPickDocumentsAt urls: [URL]) {
        // Tear down the loader BEFORE running completion callbacks so
        // any follow-on UI (toast, batched-restore wait dialog, etc.)
        // presents from a clean host VC instead of stacking on top of
        // the soon-to-be-dismissed loader.
        dismissPickerLoadingDialog()
        // Branch on `exportPickerActive` *first*. Without this the
        // export's destination URL would fall through to the
        // folder-picker branch below and `persistBookmark(url)` would
        // overwrite the cloud-folder bookmark with the just-saved
        // file's URL, breaking subsequent cloud writes.
        if exportPickerActive {
            exportPickerActive = false
            if let url = urls.first {
                Toast.showMessage(Self.formatBackupSavedMessage(forURL: url))
            } else {
                Toast.showMessage(Localization.shared.getBackupSavedShortByLangValues())
            }
            return
        }
        if controller.allowsMultipleSelection {
            restorePickerCompletion?(urls)
            restorePickerCompletion = nil
            return
        }
        // Folder picker
        guard let url = urls.first else {
            folderPickerCompletion?(false); folderPickerCompletion = nil; return
        }
        persistBookmark(url)
        folderPickerCompletion?(true)
        folderPickerCompletion = nil
    }

    public func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        dismissPickerLoadingDialog()
        if exportPickerActive {
            exportPickerActive = false
            return
        }
        folderPickerCompletion?(false); folderPickerCompletion = nil
        restorePickerCompletion?([]); restorePickerCompletion = nil
    }

    // MARK: - Toast formatting

    /// Substitute `[FOLDER]` / `[FILENAME]` placeholders in the
    /// `backup-saved` localized template with the destination URL's
    /// parent-directory name and file name. Used by both the
    /// file-export delegate path and the cloud-folder write path so
    /// the two toasts read identically.
    static func formatBackupSavedMessage(forURL url: URL) -> String {
        let folder = url.deletingLastPathComponent().lastPathComponent
        let filename = url.lastPathComponent
        return Localization.shared.getBackupSavedByLangValues()
            .replacingOccurrences(of: "[FOLDER]", with: folder)
            .replacingOccurrences(of: "[FILENAME]", with: filename)
    }
}
