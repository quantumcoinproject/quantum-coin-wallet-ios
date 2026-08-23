// DrawerView.swift
// Burger menu (Android `linearLayout_home_drawer`): a 260pt
// panel sliding in from the leading edge with Wallets, Settings and
// Advanced rows (20pt white icon + 15pt label, pressed #0FFFFFFF, 8pt
// radius) over a scrim that closes it on tap.

import UIKit

public final class DrawerView: UIView {

    public enum Item { case wallets, settings }

    public var onSelect: ((Item) -> Void)?

    private let scrim = UIView()
    private let panel = UIView()
    private var leading: NSLayoutConstraint!
    private static let width: CGFloat = 280
    private(set) var isOpen = false

    public override init(frame: CGRect) {
        super.init(frame: frame)
        isHidden = true
        scrim.backgroundColor = UIColor.black.withAlphaComponent(0.45)
        scrim.translatesAutoresizingMaskIntoConstraints = false
        scrim.addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(close)))
        let swipe = UISwipeGestureRecognizer(target: self, action: #selector(close))
        swipe.direction = .left
        addGestureRecognizer(swipe)

        panel.backgroundColor = UIColor(named: "colorBackgroundCard") ?? .systemBackground
        panel.translatesAutoresizingMaskIntoConstraints = false
        panel.layer.shadowColor = UIColor.black.cgColor
        panel.layer.shadowOpacity = 0.25
        panel.layer.shadowRadius = 10
        panel.layer.shadowOffset = CGSize(width: 2, height: 0)
        let L = Localization.shared

        // Brand header on the app gradient: header mark + title.
        let header = DrawerHeaderView()
        header.translatesAutoresizingMaskIntoConstraints = false
        panel.addSubview(header)
        let hairline = UIView()
        hairline.backgroundColor = (UIColor(named: "colorCommon6") ?? .label).withAlphaComponent(0.25)
        hairline.translatesAutoresizingMaskIntoConstraints = false
        panel.addSubview(hairline)

        let rows = UIStackView(arrangedSubviews: [
            makeRow(icon: WalletIcon.image(), sfFallback: "wallet.pass",
                    title: L.getWalletsByLangValues(), item: .wallets),
            makeRow(icon: UIImage(named: "m_settings"), sfFallback: "gearshape",
                    title: L.getSettingsByLangValues(), item: .settings)
        ])
        rows.axis = .vertical
        rows.spacing = 0
        rows.translatesAutoresizingMaskIntoConstraints = false
        panel.addSubview(rows)
        addSubview(scrim)
        addSubview(panel)
        leading = panel.leadingAnchor.constraint(equalTo: leadingAnchor, constant: -DrawerView.width)
        NSLayoutConstraint.activate([
            scrim.topAnchor.constraint(equalTo: topAnchor),
            scrim.bottomAnchor.constraint(equalTo: bottomAnchor),
            scrim.leadingAnchor.constraint(equalTo: leadingAnchor),
            scrim.trailingAnchor.constraint(equalTo: trailingAnchor),
            panel.topAnchor.constraint(equalTo: topAnchor),
            panel.bottomAnchor.constraint(equalTo: bottomAnchor),
            panel.widthAnchor.constraint(equalToConstant: DrawerView.width),
            leading,
            header.topAnchor.constraint(equalTo: panel.topAnchor),
            header.leadingAnchor.constraint(equalTo: panel.leadingAnchor),
            header.trailingAnchor.constraint(equalTo: panel.trailingAnchor),
            hairline.topAnchor.constraint(equalTo: header.bottomAnchor),
            hairline.leadingAnchor.constraint(equalTo: panel.leadingAnchor),
            hairline.trailingAnchor.constraint(equalTo: panel.trailingAnchor),
            hairline.heightAnchor.constraint(equalToConstant: 1),
            rows.topAnchor.constraint(equalTo: hairline.bottomAnchor, constant: 12),
            rows.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 10),
            rows.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -10)
        ])
    }

    required init?(coder: NSCoder) { fatalError() }

    private func makeRow(icon: UIImage?, sfFallback: String, title: String, item: Item) -> UIControl {
        let row = DrawerRowControl()
        row.layer.cornerRadius = 10
        let iv = UIImageView(image: (icon ?? UIImage(systemName: sfFallback))?.withRenderingMode(.alwaysTemplate))
        iv.tintColor = UIColor(named: "colorCommon6") ?? .label
        let chevron = UIImageView(image: UIImage(systemName: "chevron.right")?.withRenderingMode(.alwaysTemplate))
        chevron.tintColor = UIColor(named: "colorCommon10") ?? .secondaryLabel
        chevron.contentMode = .scaleAspectFit
        chevron.translatesAutoresizingMaskIntoConstraints = false
        let divider = UIView()
        divider.backgroundColor = (UIColor(named: "colorCommon6") ?? .label).withAlphaComponent(0.08)
        divider.translatesAutoresizingMaskIntoConstraints = false
        row.addSubview(chevron)
        row.addSubview(divider)
        iv.contentMode = .scaleAspectFit
        iv.translatesAutoresizingMaskIntoConstraints = false
        let label = UILabel()
        label.text = title
        label.font = Typography.boldTitle(15)
        label.textColor = UIColor(named: "colorCommon6") ?? .label
        label.translatesAutoresizingMaskIntoConstraints = false
        row.addSubview(iv)
        row.addSubview(label)
        NSLayoutConstraint.activate([
            iv.leadingAnchor.constraint(equalTo: row.leadingAnchor, constant: 14),
            iv.centerYAnchor.constraint(equalTo: row.centerYAnchor),
            iv.widthAnchor.constraint(equalToConstant: 22),
            iv.heightAnchor.constraint(equalToConstant: 22),
            label.leadingAnchor.constraint(equalTo: iv.trailingAnchor, constant: 16),
            label.centerYAnchor.constraint(equalTo: row.centerYAnchor),
            label.trailingAnchor.constraint(lessThanOrEqualTo: chevron.leadingAnchor, constant: -8),
            chevron.trailingAnchor.constraint(equalTo: row.trailingAnchor, constant: -14),
            chevron.centerYAnchor.constraint(equalTo: row.centerYAnchor),
            chevron.widthAnchor.constraint(equalToConstant: 12),
            chevron.heightAnchor.constraint(equalToConstant: 14),
            divider.leadingAnchor.constraint(equalTo: row.leadingAnchor, constant: 14),
            divider.trailingAnchor.constraint(equalTo: row.trailingAnchor, constant: -14),
            divider.bottomAnchor.constraint(equalTo: row.bottomAnchor),
            divider.heightAnchor.constraint(equalToConstant: 1),
            row.heightAnchor.constraint(equalToConstant: 52)
        ])
        row.addAction(UIAction { [weak self] _ in
            self?.close()
            self?.onSelect?(item)
        }, for: .touchUpInside)
        return row
    }

    public func open() {
        guard !isOpen else { return }
        isOpen = true
        isHidden = false
        scrim.alpha = 0
        superview?.layoutIfNeeded()
        leading.constant = 0
        UIView.animate(withDuration: 0.22) {
            self.scrim.alpha = 1
            self.superview?.layoutIfNeeded()
        }
    }

    @objc public func close() {
        guard isOpen else { return }
        isOpen = false
        leading.constant = -DrawerView.width
        UIView.animate(withDuration: 0.2, animations: {
            self.scrim.alpha = 0
            self.superview?.layoutIfNeeded()
        }, completion: { _ in
            if !self.isOpen { self.isHidden = true }
        })
    }
}

final class DrawerRowControl: UIControl {
    override var isHighlighted: Bool {
        didSet { backgroundColor = isHighlighted ? (UIColor(named: "colorCommon6") ?? .label).withAlphaComponent(0.08) : .clear }
    }
}

/// Drawer brand header: the banner gradient behind the header mark and
/// the app title.
final class DrawerHeaderView: UIView {
    private let gradient = CAGradientLayer()

    override init(frame: CGRect) {
        super.init(frame: frame)
        gradient.startPoint = CGPoint(x: 0, y: 0.5)
        gradient.endPoint = CGPoint(x: 1, y: 0.5)
        gradient.colors = [
            (UIColor(named: "colorPrimaryDarkStart") ?? UIColor(red: 0.424, green: 0.231, blue: 1.0, alpha: 1)).cgColor,
            (UIColor(named: "colorPrimaryDarkCenter") ?? UIColor(red: 0.494, green: 0.341, blue: 0.949, alpha: 1)).cgColor,
            (UIColor(named: "colorPrimaryDarkEnd") ?? UIColor(red: 0.0, green: 0.722, blue: 0.800, alpha: 1)).cgColor
        ]
        gradient.locations = [0, 0.5, 1]
        layer.insertSublayer(gradient, at: 0)

        let logo = UIImageView(image: UIImage(named: "HeaderLogo") ?? UIImage(named: "Logo"))
        logo.contentMode = .scaleAspectFit
        let title = UILabel()
        title.text = Localization.shared.getTitleByLangValues()
        title.font = Typography.boldTitle(18)
        title.textColor = UIColor(named: "colorCommon6") ?? .label
        let row = UIStackView(arrangedSubviews: [logo, title])
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 12
        row.translatesAutoresizingMaskIntoConstraints = false
        addSubview(row)
        NSLayoutConstraint.activate([
            logo.widthAnchor.constraint(equalToConstant: 44),
            logo.heightAnchor.constraint(equalToConstant: 44),
            row.topAnchor.constraint(equalTo: safeAreaLayoutGuide.topAnchor, constant: 24),
            row.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -24),
            row.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            row.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -20)
        ])
    }

    required init?(coder: NSCoder) { fatalError() }

    override func layoutSubviews() {
        super.layoutSubviews()
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        gradient.frame = bounds
        CATransaction.commit()
    }
}
