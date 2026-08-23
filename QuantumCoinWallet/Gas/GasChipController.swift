// GasChipController.swift
// Screen-level gas chip behaviour (desktop scheduleGasEstimation /
// onGasIconClick / resolveGasForTx): 2 s debounce after every input
// edit, pulsing pump + cleared label while estimating, manual override
// through the gas-config dialog that a late estimate can never
// clobber, and `ensureReady` so actions are never disabled while an
// estimate is pending. Android reference: gas/GasChipController.java

import UIKit

@MainActor
public final class GasChipController {

    public typealias PayloadProvider = () -> [String: Any]?

    public static let debounceMs: UInt64 = 2000

    public let state = GasState()
    public var kind: GasKind
    public var pairExists = true

    private weak var host: UIViewController?
    private let walletAddress: String
    private let chip: GasChipView
    private var provider: PayloadProvider?
    private var pending: Task<Void, Never>?
    private var inFlight = false
    private var onReadyWaiter: (() -> Void)?

    public init(host: UIViewController, walletAddress: String, chip: GasChipView, kind: GasKind) {
        self.host = host
        self.walletAddress = walletAddress
        self.chip = chip
        self.kind = kind
        GasIconPulse.stop(chip.iconView)
        chip.onTap = { [weak self] in self?.onIconTap() }
    }

    /// Desktop clearGasState: call on a transaction-context change
    /// (e.g. asset switch) so stale numbers never leak across kinds.
    public func reset() {
        cancelPending()
        state.reset()
        setEstimating(false)
        chip.setFeeText("")
    }

    /// Desktop scheduleGasEstimation.
    public func schedule(_ provider: @escaping PayloadProvider) {
        self.provider = provider
        cancelPending()
        let token = state.invalidate()
        if !state.overridden {
            setEstimating(true)
            chip.setFeeText("")
        }
        pending = Task { [weak self] in
            try? await Task.sleep(nanoseconds: GasChipController.debounceMs * 1_000_000)
            guard !Task.isCancelled, let self else { return }
            self.pending = nil
            await self.runEstimate(token: token)
        }
    }

    private func cancelPending() {
        pending?.cancel()
        pending = nil
    }

    private func runEstimate(token: Int) async {
        guard let payload = provider?() else {
            // Form not complete enough: clear silently, no bridge call.
            if !state.overridden {
                state.gasLimit = nil
                state.gasFeeNumber = nil
                setEstimating(false)
                chip.setFeeText("")
            }
            notifyReady()
            return
        }
        inFlight = true
        let result = await GasEstimator.estimate(walletAddress: walletAddress, kind: kind,
                                                 payload: payload, pairExists: pairExists)
        inFlight = false
        if token == state.token && !state.overridden {
            state.gasLimit = result.gasLimit
            state.gasFeeNumber = result.feeNumber
            setEstimating(false)
            chip.setFeeText(GasFee.formatQ(result.feeNumber))
        }
        notifyReady()
    }

    private func notifyReady() {
        let w = onReadyWaiter
        onReadyWaiter = nil
        w?()
    }

    /// Desktop: a click while an estimate is pending waits behind
    /// "Please wait, estimating gas..." and then proceeds.
    public func ensureReady(_ onReady: @escaping () -> Void) {
        if state.isReady || (pending == nil && !inFlight) {
            onReady()
            return
        }
        let wait = WaitDialogViewController(message: Localization.shared.lang(
            "pleaseWaitEstimatingGas", fallback: "Please wait, estimating gas..."))
        host?.present(wait, animated: true)
        onReadyWaiter = { [weak wait] in
            wait?.dismiss(animated: true) { onReady() }
        }
        if pending != nil {
            // Flush the debounce now.
            cancelPending()
            let token = state.token
            Task { [weak self] in await self?.runEstimate(token: token) }
        }
    }

    /// Desktop resolveGasForTx for this chip.
    public func resolve() -> (gasLimit: Int64, feeNumber: String) {
        GasEstimator.resolve(state: state, kind: kind, pairExists: pairExists,
                             walletAddress: walletAddress)
    }

    private func onIconTap() {
        guard let host else { return }
        let dlg = GasConfigDialogViewController(gasLimit: state.gasLimit,
                                                feeNumber: state.gasFeeNumber)
        dlg.onOk = { [weak self] limit, fee in
            guard let self else { return }
            self.cancelPending()
            self.state.invalidate()
            self.state.gasLimit = limit
            self.state.gasFeeNumber = fee
            self.state.overridden = true
            self.setEstimating(false)
            self.chip.setFeeText(GasFee.formatQ(fee))
        }
        host.present(dlg, animated: true)
    }

    private func setEstimating(_ estimating: Bool) {
        if estimating { GasIconPulse.start(chip.iconView) } else { GasIconPulse.stop(chip.iconView) }
        chip.isHidden = false
    }
}
