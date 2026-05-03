// QRScannerViewController.swift
// Lightweight `AVCaptureSession`-backed QR scanner used by the Send
// screen for "scan a recipient address" parity with Android's
// `BarcodeScannerActivity` (which uses ML Kit / ZXing). For our use
// case AVFoundation's built-in `.qr` metadata scanner is sufficient
// — recipient addresses are short ASCII strings and we don't need
// ML Kit's multi-format detection.
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/activities/BarcodeScannerActivity.java

import AVFoundation
import UIKit

public final class QRScannerViewController: UIViewController {

    /// Fired on the main queue with the first scanned QR payload.
    /// The host VC is responsible for dismissing this controller.
    public var onScan: ((String) -> Void)?

    /// Fired on the main queue when the capture session can't be
    /// configured -- e.g. no rear-facing camera (Simulator), the
    /// device input cannot be added, or the metadata output is
    /// rejected. The host should surface a user-facing error dialog.
    /// Independent of camera-permission denial: that branch is
    /// gated upstream by `AVCaptureDevice.authorizationStatus`.
    public var onConfigurationFailure: (() -> Void)?

    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private let metadataOutput = AVCaptureMetadataOutput()
    private var didReport = false

    private let cancelButton: UIButton = {
        let b = UIButton(type: .system)
        b.setTitle(Localization.shared.getCancelByLangValues(), for: .normal)
        b.setTitleColor(.white, for: .normal)
        b.titleLabel?.font = Typography.mediumLabel(15)
        b.backgroundColor = UIColor.black.withAlphaComponent(0.5)
        b.layer.cornerRadius = 18
        b.contentEdgeInsets = UIEdgeInsets(top: 6, left: 18, bottom: 6, right: 18)
        b.translatesAutoresizingMaskIntoConstraints = false
        return b
    }()

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        cancelButton.addTarget(self, action: #selector(tapCancel), for: .touchUpInside)
        view.addSubview(cancelButton)
        NSLayoutConstraint.activate([
                cancelButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor,
                    constant: -24),
                cancelButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
                cancelButton.heightAnchor.constraint(equalToConstant: 36)
            ])

        configureSession()
    }

    public override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if !session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.session.startRunning()
            }
        }
    }

    public override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning { session.stopRunning() }
    }

    public override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
        view.bringSubviewToFront(cancelButton)
    }

    private func configureSession() {
        guard let device = AVCaptureDevice.default(for: .video),
        let input = try? AVCaptureDeviceInput(device: device),
        session.canAddInput(input) else {
            failAndDismiss()
            return
        }
        session.beginConfiguration()
        session.addInput(input)
        if session.canAddOutput(metadataOutput) {
            session.addOutput(metadataOutput)
            metadataOutput.setMetadataObjectsDelegate(self, queue: .main)
            metadataOutput.metadataObjectTypes = [.qr]
        } else {
            session.commitConfiguration()
            failAndDismiss()
            return
        }
        session.commitConfiguration()

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.insertSublayer(preview, at: 0)
        previewLayer = preview
    }

    /// Capture session couldn't be brought up. This is *not* a
    /// permission failure (those are caught upstream), so we route
    /// the host through `onConfigurationFailure` so the host can
    /// raise a generic error dialog after the scanner has dismissed.
    private func failAndDismiss() {
        let handler = onConfigurationFailure
        dismiss(animated: true) { handler?() }
    }

    @objc private func tapCancel() {
        dismiss(animated: true)
    }
}

extension QRScannerViewController: AVCaptureMetadataOutputObjectsDelegate {

    public func metadataOutput(_ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection) {
        guard !didReport,
        let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
        let value = obj.stringValue else { return }
        didReport = true
        if session.isRunning { session.stopRunning() }
        onScan?(value)
    }
}
