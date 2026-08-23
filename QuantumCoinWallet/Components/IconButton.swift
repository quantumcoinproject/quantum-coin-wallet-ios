// IconButton.swift
// Template-tinted square icon button (Android ImageButton with
// image_selector background): copy / block-explorer affordances on
// hash rows, result blocks and position cards.

import UIKit

public enum IconButton {
    public static func make(named: String, size: CGFloat = 36, padding: CGFloat = 6,
                            tint: UIColor = UIColor(named: "colorCommon6") ?? .label,
                            accessibility: String, action: @escaping () -> Void) -> UIButton {
        let b = UIButton(type: .custom)
        b.setImage(UIImage(named: named)?.withRenderingMode(.alwaysTemplate), for: .normal)
        b.tintColor = tint
        b.imageView?.contentMode = .scaleAspectFit
        b.contentEdgeInsets = UIEdgeInsets(top: padding, left: padding, bottom: padding, right: padding)
        b.widthAnchor.constraint(equalToConstant: size).isActive = true
        b.heightAnchor.constraint(equalToConstant: size).isActive = true
        b.accessibilityLabel = accessibility
        b.addAction(UIAction(handler: { _ in action() }), for: .touchUpInside)
        return b
    }

    /// Copy + explorer pair for a tx hash (Android tx_steps_dialog hash row).
    public static func copyAndExplorer(copyValue: @escaping () -> String?,
                                       explorerUrl: @escaping () -> URL?) -> UIStackView {
        let L = Localization.shared
        let copy = make(named: "copy_outline", accessibility: L.getCopyByLangValues()) {
            guard let v = copyValue(), !v.isEmpty else { return }
            Pasteboard.copySensitive(v)
            Toast.showMessage(L.getCopiedByLangValues())
        }
        let explorer = make(named: "address_explore",
                            accessibility: L.getBlockExplorerTitleByLangValues()) {
            guard let url = explorerUrl() else {
                Toast.showError(L.getNoActiveNetworkByLangValues())
                return
            }
            UIApplication.shared.open(url)
        }
        let row = UIStackView(arrangedSubviews: [copy, explorer])
        row.axis = .horizontal
        row.spacing = 4
        row.alignment = .center
        return row
    }
}
