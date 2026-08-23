// GasChipView.swift
// Desktop `.gas-header-right`: "<fee> Q" label + 38pt gas pump. The
// pump pulses while an estimate is in flight (GasIconPulse) and opens
// the gas-config dialog on tap. Android reference: the
// textView_*_gas_fee / imageView_*_gas_icon pairs in send_fragment.xml,
// pools_fragment.xml, token_create_fragment.xml, tx_steps_dialog.xml.

import UIKit

public final class GasChipView: UIView {

    public let feeLabel: UILabel = {
        let l = UILabel()
        l.font = Typography.body(12)
        l.textColor = UIColor(named: "colorCommon10") ?? .secondaryLabel
        l.textAlignment = .right
        return l
    }()

    public let iconView: UIImageView = {
        let iv = UIImageView(image: UIImage(named: "ic_gas_outline"))
        iv.contentMode = .scaleAspectFit
        iv.isUserInteractionEnabled = true
        iv.isAccessibilityElement = true
        iv.accessibilityLabel = "Gas"
        iv.accessibilityTraits = .button
        return iv
    }()

    public var onTap: (() -> Void)?

    public override init(frame: CGRect) {
        super.init(frame: frame)
        let stack = UIStackView(arrangedSubviews: [feeLabel, iconView])
        stack.axis = .horizontal
        stack.alignment = .center
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: topAnchor),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 38),
            iconView.heightAnchor.constraint(equalToConstant: 38)
        ])
        let tap = UITapGestureRecognizer(target: self, action: #selector(handleTap))
        iconView.addGestureRecognizer(tap)
        let press = UILongPressGestureRecognizer(target: self, action: #selector(handlePress(_:)))
        press.minimumPressDuration = 0
        press.cancelsTouchesInView = false
        press.delegate = self
        iconView.addGestureRecognizer(press)
    }

    required init?(coder: NSCoder) { fatalError() }

    public func setFeeText(_ text: String) {
        feeLabel.text = text
    }

    @objc private func handleTap() {
        onTap?()
    }

    /// Desktop gas_icon_selector: pressed state swaps to the "active"
    /// artwork; restored on release (unless pulsing).
    @objc private func handlePress(_ g: UILongPressGestureRecognizer) {
        guard iconView.layer.animation(forKey: "gasPulse") == nil else { return }
        switch g.state {
        case .began: iconView.image = UIImage(named: "ic_gas_active")
        case .ended, .cancelled, .failed: iconView.image = UIImage(named: "ic_gas_outline")
        default: break
        }
    }
}

extension GasChipView: UIGestureRecognizerDelegate {
    public func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer,
                                  shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool {
        true
    }
}
