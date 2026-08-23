// ExplorerLinks.swift
// Block-explorer link rendering: a whole value as a teal underlined
// link (review-dialog rows, result blocks) and "A / B" pair labels
// whose symbols each link to the token contract. URLs only ever come
// from `UrlBuilder` (strict address validation). Android reference:
// view/widget/ExplorerLinks.java

import UIKit

public enum ExplorerLinks {

    /// A tappable value label (teal, underlined) that opens `url`.
    /// When `url` is nil the plain value is shown (selectable text).
    public static func makeValueLabel(_ value: String, url: URL?, mono: Bool,
                                      size: CGFloat = 12, color: UIColor = UIColor(named: "colorCommon6") ?? .label) -> UIView {
        let tv = UITextView()
        tv.isEditable = false
        tv.isScrollEnabled = false
        tv.backgroundColor = .clear
        tv.textContainerInset = .zero
        tv.textContainer.lineFragmentPadding = 0
        tv.textContainer.lineBreakMode = .byCharWrapping
        tv.dataDetectorTypes = []
        let font = mono ? UIFont.monospacedSystemFont(ofSize: size, weight: .regular) : Typography.body(size)
        if let url {
            let attrs: [NSAttributedString.Key: Any] = [
                .font: font, .foregroundColor: UIColor.systemBlue,
                .underlineStyle: NSUnderlineStyle.single.rawValue,
                .link: url
            ]
            tv.attributedText = NSAttributedString(string: value, attributes: attrs)
            tv.linkTextAttributes = [.foregroundColor: UIColor.systemBlue,
                                     .underlineStyle: NSUnderlineStyle.single.rawValue]
            tv.isSelectable = true
            tv.delegate = LinkOpener.shared
        } else {
            tv.attributedText = NSAttributedString(string: value,
                attributes: [.font: font, .foregroundColor: color])
            tv.isSelectable = true
        }
        return tv
    }

    /// "A / B" where each symbol links to its token contract.
    public static func makePairLabel(symA: String, tokenA: String, symB: String, tokenB: String,
                                     size: CGFloat = 15) -> UITextView {
        let tv = UITextView()
        tv.isEditable = false
        tv.isScrollEnabled = false
        tv.backgroundColor = .clear
        tv.textContainerInset = .zero
        tv.textContainer.lineFragmentPadding = 0
        tv.dataDetectorTypes = []
        let font = Typography.boldTitle(size)
        let s = NSMutableAttributedString()
        appendToken(s, symA, tokenA, font: font)
        s.append(NSAttributedString(string: " / ",
            attributes: [.font: font, .foregroundColor: UIColor(named: "colorCommon6") ?? .label]))
        appendToken(s, symB, tokenB, font: font)
        tv.attributedText = s
        tv.linkTextAttributes = [.foregroundColor: UIColor.systemBlue]
        tv.isSelectable = true
        tv.delegate = LinkOpener.shared
        return tv
    }

    private static func appendToken(_ s: NSMutableAttributedString, _ label: String,
                                    _ token: String, font: UIFont) {
        var attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: UIColor.systemBlue]
        if let url = UrlBuilder.tokenUrl(token) { attrs[.link] = url }
        s.append(NSAttributedString(string: label, attributes: attrs))
    }

    public static func open(_ url: URL?) {
        guard let url else { return }
        UIApplication.shared.open(url)
    }

    /// Opens links through UIApplication (so SFSafariViewController /
    /// default browser policy stays consistent) and disables the
    /// text-selection menu on link text.
    final class LinkOpener: NSObject, UITextViewDelegate {
        static let shared = LinkOpener()

        func textView(_ textView: UITextView, shouldInteractWith URL: URL,
                      in characterRange: NSRange, interaction: UITextItemInteraction) -> Bool {
            if interaction == .invokeDefaultAction {
                UIApplication.shared.open(URL)
            }
            return false
        }
    }
}
