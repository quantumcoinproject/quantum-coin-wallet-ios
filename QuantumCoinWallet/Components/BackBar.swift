// BackBar.swift
// Shared 44pt-tall back-arrow row used at the top of secondary
// screens (Networks, Add Network, Settings, etc.). Promoted out of
// `BlockchainNetworkViewController.swift` so any UIViewController
// that needs the same chrome can call `makeBackBar(action:)` without
// re-implementing the same image button + spacer pattern.
// Visual + tap behaviour mirror Android `imageButton_*_back_arrow`:
// 32x32 templated `arrow_back_circle_outline` tinted to
// `colorCommon6`, with a leading position and a flexible spacer so
// any title text added to the same row trails to the right.

import UIKit

internal extension UIViewController {
    /// 44pt-tall row containing a 32x32 back-arrow image button on the
    /// leading edge. The supplied selector is wired to `self` via
    /// `addTarget(_:action:for:)`.
    func makeBackBar(action: Selector) -> UIView {
        return makeBackBar(backAction: action, refreshAction: nil)
    }

    /// 44pt-tall row containing a 32x32 back-arrow image button on the
    /// leading edge, optionally followed by a 32x32 refresh image
    /// button. Mirrors the Android `top_linear_layout_account_transactions_id`
    /// row from `account_transactions_fragment.xml`, where back +
    /// refresh sit side by side with a flexible spacer trailing.
    /// `backAction` and `refreshAction` selectors target `self`.
    func makeBackBar(backAction: Selector,
        refreshAction: Selector?) -> UIView {
        let row = UIStackView()
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 8
        row.heightAnchor.constraint(equalToConstant: 44).isActive = true

        let back = makeChromeImageButton(
            named: "arrow_back_circle_outline",
            action: backAction)
        row.addArrangedSubview(back)

        if let refreshAction = refreshAction {
            let refresh = makeChromeImageButton(
                named: "retry",
                action: refreshAction)
            row.addArrangedSubview(refresh)
        }

        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
    }

    /// 32x32 templated image button tinted to `colorCommon6`. Shared by
    /// the back / refresh slots in `makeBackBar(backAction:refreshAction:)`.
    private func makeChromeImageButton(named: String, action: Selector) -> UIButton {
        let b = UIButton(type: .custom)
        let img = UIImage(named: named)?
        .withRenderingMode(.alwaysTemplate)
        b.setImage(img, for: .normal)
        b.tintColor = UIColor(named: "colorCommon6") ?? .label
        b.adjustsImageWhenHighlighted = true
        b.widthAnchor.constraint(equalToConstant: 32).isActive = true
        b.heightAnchor.constraint(equalToConstant: 32).isActive = true
        b.addTarget(self, action: action, for: .touchUpInside)
        return b
    }
}
