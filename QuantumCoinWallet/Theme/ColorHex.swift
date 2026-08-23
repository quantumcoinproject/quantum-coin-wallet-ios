import UIKit

// Android-style 0xAARRGGBB literals (layouts/drawables in the Android
// app use alpha-prefixed hex everywhere). Shared by chrome, dialogs and
// the DEX screens so colour values can be copied verbatim.
public extension UIColor {
    convenience init(argbHex: UInt32) {
        let a = CGFloat((argbHex >> 24) & 0xFF) / 255.0
        let r = CGFloat((argbHex >> 16) & 0xFF) / 255.0
        let g = CGFloat((argbHex >> 8) & 0xFF) / 255.0
        let b = CGFloat( argbHex & 0xFF) / 255.0
        self.init(red: r, green: g, blue: b, alpha: a)
    }

    /// Opaque 0xRRGGBB literal.
    convenience init(rgbHex: UInt32) {
        self.init(argbHex: 0xFF000000 | (rgbHex & 0xFFFFFF))
    }

    /// Asset-catalog colour with a literal fallback.
    static func named(_ name: String, fallback: UInt32) -> UIColor {
        UIColor(named: name) ?? UIColor(rgbHex: fallback)
    }
}
