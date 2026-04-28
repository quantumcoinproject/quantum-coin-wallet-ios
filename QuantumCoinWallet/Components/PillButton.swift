//
// PillButton.swift
//
// Shared rounded "pill" buttons used by the seed-quiz Next button,
// the network-select dialog, and any future surface that wants to
// match the Android primary / secondary action button shape.
//
// `GreenPillButton` is the purple `#7d44aa` primary action mirroring
// Android `drawable/button_green_shadow.xml` (the drawable is named
// "green" but is actually purple in the theme).
//
// `GrayPillButton` is the secondary action mirroring Android's
// `drawable/button_gray_shadow.xml` (used for `Cancel` in dialogs).
//
// Both classes share an identical pill geometry (corner radius 16,
// inset content edges, bold 16pt title, white title colour) so they
// line up cleanly when placed side-by-side in a `.fillEqually`
// `UIStackView`.
//
// Both classes also carry the same drop shadow style as the
// home-screen Send / Receive cards (see `ChromeViews.swift` line
// 370 and `ShapeFactory.swift` line 54). Because the shadow has to
// render outside the button bounds, neither class clips to its
// layer. `applyStyle()` sets the shadow values; `layoutSubviews()`
// re-applies them and refreshes the `shadowPath` so the shadow
// stays in sync if a hosting screen rebuilds its layout (and so
// the shadow is restored even if `init(frame:)` was somehow not
// the route used to construct the button -- belt-and-braces against
// `UIButton(type:)`'s historically quirky initializer dispatch).
//
// Android reference:
//   app/src/main/res/drawable/button_green_shadow.xml
//   app/src/main/res/drawable/button_gray_shadow.xml
//

import UIKit

/// Solid `#7d44aa` rounded pill mirroring Android's
/// `drawable/button_green_shadow.xml` (yes, the file is misnamed -
/// the drawable itself is purple).
public final class GreenPillButton: UIButton {
    public override init(frame: CGRect) {
        super.init(frame: frame)
        applyStyle()
    }
    public required init?(coder: NSCoder) {
        super.init(coder: coder)
        applyStyle()
    }

    public override func layoutSubviews() {
        super.layoutSubviews()
        applyShadow(to: self)
    }

    private func applyStyle() {
        let purple = UIColor(red: 0x7D / 255.0, green: 0x44 / 255.0, blue: 0xAA / 255.0, alpha: 1)
        backgroundColor = purple
        layer.cornerRadius = 16
        layer.borderColor = purple.cgColor
        layer.borderWidth = 1
        applyShadow(to: self)
        setTitleColor(UIColor(named: "colorCommon7") ?? .white, for: .normal)
        titleLabel?.font = Typography.boldTitle(16)
        contentEdgeInsets = UIEdgeInsets(top: 5, left: 16, bottom: 5, right: 16)
    }
}

/// Solid gray rounded pill mirroring Android's
/// `drawable/button_gray_shadow.xml`. Used for the secondary
/// (Cancel) action in dialogs that pair it with `GreenPillButton`.
public final class GrayPillButton: UIButton {
    public override init(frame: CGRect) {
        super.init(frame: frame)
        applyStyle()
    }
    public required init?(coder: NSCoder) {
        super.init(coder: coder)
        applyStyle()
    }

    public override func layoutSubviews() {
        super.layoutSubviews()
        applyShadow(to: self)
    }

    private func applyStyle() {
        // Android `button_gray_shadow.xml` uses `@color/colorCommon3`
        // (`#807D7D`) as a hard-coded gray that does NOT swap to white
        // in night mode. The iOS `colorCommon3` asset is theme-aware
        // and resolves to white in dark mode, which would be wrong
        // here -- the Cancel pill must read as solid gray on every
        // background, exactly like Android. So we hard-code the hex
        // and skip the asset catalog.
        let gray = UIColor(red: 0x80 / 255.0, green: 0x7D / 255.0, blue: 0x7D / 255.0, alpha: 1)
        backgroundColor = gray
        layer.cornerRadius = 16
        layer.borderColor = gray.cgColor
        layer.borderWidth = 1
        applyShadow(to: self)
        setTitleColor(UIColor(named: "colorCommon7") ?? .white, for: .normal)
        titleLabel?.font = Typography.boldTitle(16)
        contentEdgeInsets = UIEdgeInsets(top: 5, left: 16, bottom: 5, right: 16)
    }
}

/// Apply the shared pill-button drop shadow. Pulled into a free
/// function so both `GreenPillButton.applyStyle()` /
/// `layoutSubviews()` and `GrayPillButton.applyStyle()` /
/// `layoutSubviews()` use the exact same parameters and refresh the
/// shadowPath whenever the layer's bounds change. Slightly heavier
/// than the Send / Receive `colorCardA/B` cards (which carry their
/// own shadow at opacity 0.20) so the smaller pill silhouette still
/// reads as elevated against the white dialog / quiz cards.
private func applyShadow(to button: UIButton) {
    button.clipsToBounds = false
    button.layer.masksToBounds = false
    button.layer.shadowColor = UIColor.black.cgColor
    button.layer.shadowOffset = CGSize(width: 0, height: 3)
    button.layer.shadowRadius = 6
    button.layer.shadowOpacity = 0.30
    if !button.bounds.isEmpty {
        button.layer.shadowPath = UIBezierPath(
            roundedRect: button.bounds,
            cornerRadius: button.layer.cornerRadius).cgPath
    } else {
        button.layer.shadowPath = nil
    }
}
