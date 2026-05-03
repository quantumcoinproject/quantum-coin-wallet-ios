// Toast.swift
// Transient toast-like banner at the top of the key window. Port of
// Android `GlobalMethods.ShowToast` / `ShowErrorDialog` / `ShowMessageDialog`.

import UIKit

public enum Toast {

    public static func show(_ message: String, duration: TimeInterval = 2.5,
        style: Style = .info) {
        guard let window = keyWindow else { return }
        let toast = ToastView(message: message, style: style)
        toast.translatesAutoresizingMaskIntoConstraints = false
        window.addSubview(toast)
        NSLayoutConstraint.activate([
                toast.leadingAnchor.constraint(greaterThanOrEqualTo: window.leadingAnchor, constant: 16),
                toast.trailingAnchor.constraint(lessThanOrEqualTo: window.trailingAnchor, constant: -16),
                toast.centerXAnchor.constraint(equalTo: window.centerXAnchor),
                toast.topAnchor.constraint(equalTo: window.safeAreaLayoutGuide.topAnchor, constant: 8)
            ])
        toast.alpha = 0
        UIView.animate(withDuration: 0.2, animations: { toast.alpha = 1 })
        DispatchQueue.main.asyncAfter(deadline: .now() + duration) {
            UIView.animate(withDuration: 0.2, animations: { toast.alpha = 0 },
                completion: { _ in toast.removeFromSuperview() })
        }
    }

    public static func showError(_ message: String) { show(message, style: .error) }

    public static func showMessage(_ message: String) { show(message, style: .info) }

    public enum Style { case info, error }

    private static var keyWindow: UIWindow? {
        UIApplication.shared.connectedScenes
        .compactMap { ($0 as? UIWindowScene)?.keyWindow }
        .first
    }
}

private final class ToastView: UIView {
    init(message: String, style: Toast.Style) {
        super.init(frame: .zero)
        backgroundColor = (style == .error)
        ? UIColor.systemRed.withAlphaComponent(0.95)
        : UIColor.black.withAlphaComponent(0.85)
        layer.cornerRadius = 10
        layer.masksToBounds = true

        let label = UILabel()
        label.text = message
        label.font = Typography.body(14)
        label.textColor = .white
        label.numberOfLines = 0
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        addSubview(label)
        NSLayoutConstraint.activate([
                label.topAnchor.constraint(equalTo: topAnchor, constant: 10),
                label.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -10),
                label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 14),
                label.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -14)
            ])
    }
    required init?(coder: NSCoder) { fatalError() }
}
