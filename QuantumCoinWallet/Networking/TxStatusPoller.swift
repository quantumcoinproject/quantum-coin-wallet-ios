// TxStatusPoller.swift
// Desktop lib/api.ts getTransactionStatusByHash + waitForTxSuccess:
// page 0 of the PENDING list first (hash there => still pending), then
// page 0 of the COMPLETED list (hash there => succeeded / failed by the
// item's status), otherwise unknown. API errors also map to unknown so
// a transient scan-API hiccup never terminates the loop.
// Android reference: networking/TxStatusPoller.java
//
// Callers: send-completed dialog (9000 ms, unlimited, immediate) and
// the tx-steps dialog (5000 ms, 120 polls, sleep first).

import Foundation

@MainActor
public final class TxStatusPoller {

    public enum Status: String {
        case pending, succeeded, failed, unknown
    }

    public struct Listener {
        public var onSucceeded: () -> Void
        public var onFailed: (String?) -> Void
        /// Only when `maxPolls > 0`.
        public var onTimeout: () -> Void

        public init(onSucceeded: @escaping () -> Void,
                    onFailed: @escaping (String?) -> Void,
                    onTimeout: @escaping () -> Void = { }) {
            self.onSucceeded = onSucceeded
            self.onFailed = onFailed
            self.onTimeout = onTimeout
        }
    }

    private let address: String
    private let txHash: String
    private let intervalMs: Int
    private let maxPolls: Int
    private let sleepFirst: Bool
    private let listener: Listener
    private var task: Task<Void, Never>?
    private var cancelled = false

    public init(address: String, txHash: String, intervalMs: Int, maxPolls: Int,
                sleepFirst: Bool, listener: Listener) {
        self.address = address
        self.txHash = txHash
        self.intervalMs = intervalMs
        self.maxPolls = maxPolls
        self.sleepFirst = sleepFirst
        self.listener = listener
    }

    @discardableResult
    public static func start(address: String, txHash: String, intervalMs: Int, maxPolls: Int,
                             sleepFirst: Bool, listener: Listener) -> TxStatusPoller {
        let p = TxStatusPoller(address: address, txHash: txHash, intervalMs: intervalMs,
                               maxPolls: maxPolls, sleepFirst: sleepFirst, listener: listener)
        p.start()
        return p
    }

    public func start() {
        guard task == nil else { return }
        task = Task { [weak self] in
            guard let self else { return }
            var polls = 0
            if self.sleepFirst { await self.sleep() }
            while !Task.isCancelled && !self.cancelled {
                if self.maxPolls > 0 && polls >= self.maxPolls {
                    self.listener.onTimeout()
                    return
                }
                polls += 1
                let status = await TxStatusPoller.checkStatus(address: self.address, txHash: self.txHash)
                if Task.isCancelled || self.cancelled { return }
                switch status {
                case .succeeded:
                    self.listener.onSucceeded()
                    return
                case .failed:
                    self.listener.onFailed(nil)
                    return
                case .pending, .unknown:
                    break
                }
                await self.sleep()
            }
        }
    }

    public func cancel() {
        cancelled = true
        task?.cancel()
        task = nil
    }

    private func sleep() async {
        try? await Task.sleep(nanoseconds: UInt64(max(intervalMs, 0)) * 1_000_000)
    }

    // MARK: - Status resolution

    /// One scan-API round: pending page 0, then completed page 0.
    public static func checkStatus(address: String, txHash: String) async -> Status {
        do {
            let pending = try await AccountsApi.accountPendingTransactions(address: address, pageIndex: 0)
            if contains(pending.result, txHash) { return .pending }
            let completed = try await AccountsApi.accountTransactions(address: address, pageIndex: 0)
            return status(pending: [], completed: completed.result ?? [], txHash: txHash)
        } catch {
            return .unknown
        }
    }

    /// Pure mapping (unit-tested): hash in pending → pending; hash in
    /// completed → succeeded iff its status is a success marker, else
    /// failed; neither → unknown. Hash comparison is case-insensitive.
    public static func status(pending: [AccountTransaction], completed: [AccountTransaction],
                              txHash: String) -> Status {
        if contains(pending, txHash) { return .pending }
        if let tx = completed.first(where: { ($0.hash ?? "").caseInsensitiveCompare(txHash) == .orderedSame }) {
            let raw: Any? = tx.status ?? tx.receipt?.status
            return isSuccess(raw) ? .succeeded : .failed
        }
        return .unknown
    }

    /// Desktop maps `status == "0x1"` to success; the scan API may also
    /// surface a boolean or a bare number.
    public static func isSuccess(_ status: Any?) -> Bool {
        if let b = status as? Bool { return b }
        if let n = status as? Int { return n == 1 }
        if let n = status as? NSNumber { return n.intValue == 1 }
        if let s = status as? String {
            let t = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return t == "0x1" || t == "1" || t == "true"
        }
        return false
    }

    private static func contains(_ list: [AccountTransaction]?, _ txHash: String) -> Bool {
        (list ?? []).contains { ($0.hash ?? "").caseInsensitiveCompare(txHash) == .orderedSame }
    }
}
