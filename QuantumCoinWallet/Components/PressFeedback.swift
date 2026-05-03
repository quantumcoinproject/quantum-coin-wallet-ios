// PressFeedback.swift
// Uniform tap / press visual feedback for every interactive surface in the
// app. Mirrors the Android app's `image_selector` / `text_link_selector_bg`
// "press dim" affordance with an iOS-native alpha fade.
// Behaviour:
// - On `.touchDown` / `.touchDragEnter` the control fades to alpha 0.55
// in 80ms.
// - On `.touchUpInside` / `.touchUpOutside` / `.touchCancel` /
// `.touchDragExit` it fades back to alpha 1.0 in 80ms.
// - The dim persists while the finger is held down (matches Android's
// pressed-state which stays painted until release).
// Idempotent - calling `enablePressFeedback` more than once on the same
// control is a no-op. We track the install via a UInt8-keyed associated
// object so we don't accumulate `UIAction`s.
// Some control kinds run their own native animations and must NOT be dimmed
// (UISegmentedControl, UISwitch, UISlider, UITextField, UIPageControl).
// Those are skipped by `enablePressFeedback` and by the recursive walker.

import UIKit

enum PressFeedback {
    static let dimmedAlpha: CGFloat = 0.55
    static let animationDuration: TimeInterval = 0.08
}

private var installedKey: UInt8 = 0

extension UIControl {

    /// Attach the standard press-fade to this control. Idempotent.
    /// No-op for controls that own their own press animation
    /// (segmented controls, switches, sliders, page controls, text fields).
    func enablePressFeedback() {
        if PressFeedback_isDenied(self) { return }
        if objc_getAssociatedObject(self, &installedKey) != nil { return }
        objc_setAssociatedObject(self, &installedKey, true,
            .OBJC_ASSOCIATION_RETAIN_NONATOMIC)

        // Defensive: a freshly added control should always render at full
        // opacity, not inherit a stuck-dim alpha from a previous lifecycle.
        alpha = 1.0

        addAction(UIAction(handler: { [weak self] _ in
                self?.pressFeedback_dim()
            }), for: [.touchDown, .touchDragEnter])

        addAction(UIAction(handler: { [weak self] _ in
                self?.pressFeedback_restore()
            }), for: [.touchUpInside, .touchUpOutside, .touchCancel, .touchDragExit])
    }

    private func pressFeedback_dim() {
        UIView.animate(withDuration: PressFeedback.animationDuration,
            delay: 0,
            options: [.beginFromCurrentState, .allowUserInteraction],
            animations: { self.alpha = PressFeedback.dimmedAlpha },
            completion: nil)
    }

    private func pressFeedback_restore() {
        UIView.animate(withDuration: PressFeedback.animationDuration,
            delay: 0,
            options: [.beginFromCurrentState, .allowUserInteraction],
            animations: { self.alpha = 1.0 },
            completion: nil)
    }
}

extension UIView {

    /// Walk the subview tree and install press feedback on every
    /// non-deny-listed `UIControl`. Safe to call repeatedly - the per-control
    /// guard prevents duplicate target wiring.
    func installPressFeedbackRecursive() {
        if let control = self as? UIControl {
            control.enablePressFeedback()
        }
        for sub in subviews {
            sub.installPressFeedbackRecursive()
        }
    }
}

private func PressFeedback_isDenied(_ control: UIControl) -> Bool {
    return control is UISegmentedControl
    || control is UISwitch
    || control is UISlider
    || control is UIPageControl
    || control is UITextField
}
