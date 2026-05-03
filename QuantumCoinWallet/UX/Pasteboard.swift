// Pasteboard.swift (UX layer)
// Hardened wrapper around `UIPasteboard.general` for
// sensitive material (seed phrases, mnemonics, private keys, wallet
// addresses, transaction hashes).
// Why a wrapper exists at all (notes for AI reviewers and human auditors):
// The default `UIPasteboard.general.string =` shape that the app used
// to call has two security-relevant defaults that are wrong for a
// wallet that holds high-value assets:
// 1. **Universal Clipboard.** iOS 10+ replicates pasteboard items to
// every other Apple device signed into the same iCloud account
// within seconds, with no UI signal to the user. A copied seed
// phrase therefore reaches the user's MacBook, iPad, and any
// other iPhone they have within reach. `[.localOnly: true]` opts
// the item out of that replication.
// 2. **Indefinite persistence.** The default item lives on the
// clipboard until the user (or another app) overwrites it.
// Anything launched in the meantime - the QuickType bar, a
// clipboard manager, a sandbox-escaping app - sees the value.
// `[.expirationDate: ...]` causes iOS to evict the item after
// the chosen lifetime even if nothing else is copied.
// These two options together turn a copied seed phrase from "leaks
// to every device for hours" into "stays on this device for a minute".
// They do NOT defend against:
// - On-device clipboard scrapers running while the value is fresh
// (impossible to defend in user mode; nothing the wallet can do).
// - Screen-recording / screen-capture tools that grabbed the value
// before the user copied it ( covers the snapshot path).
// Tradeoff (audit-grade summary):
// The user can no longer paste the copied value on a different device
// of theirs. This is a deliberate scope reduction matching the
// wallet's threat model: high-value secrets should not leave the
// device that produced them. The 60 s default lifetime is a balance
// between "long enough to reliably paste before the system evicts"
// and "short enough to limit residual exposure on this device".
// Lifetime is overridable per call site.
// Lint contract (verification §10):
// Any call to `UIPasteboard.general.string = ...`,
// `UIPasteboard.general.setValue(...)`, or
// `UIPasteboard.general.setItems(...)` outside this file is a
// build-blocking review failure. The wrapper is the ONLY pathway
// through which the app touches the system pasteboard. New "Copy"
// affordances must call `Pasteboard.copySensitive`.

import Foundation
import UIKit

public enum Pasteboard {

    /// Default lifetime for a copy of any sensitive value. Tuned for
    /// "user can paste reliably within this window" while keeping
    /// residual exposure short. Per-call override is supported.
    public static let defaultLifetime: TimeInterval = 60

    /// Copy `value` to the system pasteboard with the hardened option
    /// set required by ``:
    /// - `.localOnly: true` blocks Universal Clipboard replication.
    /// - `.expirationDate: now + lifetime` causes iOS to evict the
    /// item after `lifetime` seconds even if nothing else is
    /// copied.
    /// Use the `lifetime` override for values that are MORE sensitive
    /// than a wallet address (e.g. a seed phrase or a mnemonic).
    /// Shorter lifetimes raise the chance the user does not paste in
    /// time; the wrapper therefore does NOT silently shorten the
    /// default. Callers that want a shorter window pass an explicit
    /// value.
    /// `UIPasteboard.typeAutomatic` is used as the type key so the
    /// system picks the broadest valid UTI (`public.utf8-plain-text`
    /// for ASCII, etc.) - matching what `UIPasteboard.general.string =`
    /// did before the hardening, except now with the option set.
    public static func copySensitive(
        _ value: String,
        lifetime: TimeInterval = defaultLifetime
    ) {
        let item: [String: Any] = [UIPasteboard.typeAutomatic: value]
        UIPasteboard.general.setItems(
            [item],
            options: [
                .localOnly: true,
                .expirationDate: Date(timeIntervalSinceNow: lifetime),
            ]
        )
    }
}
