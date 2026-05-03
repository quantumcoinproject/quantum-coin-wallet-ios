// Typography.swift
// Maps Android's `relay_poppins_*` font families to iOS system font
// weights. See `ios_clone_spec` §3.2 for rationale.

import UIKit

public enum Typography {

    public static func body(_ size: CGFloat) -> UIFont {
        UIFont.systemFont(ofSize: size, weight: .regular)
    }

    public static func mediumLabel(_ size: CGFloat) -> UIFont {
        UIFont.systemFont(ofSize: size, weight: .medium)
    }

    public static func boldTitle(_ size: CGFloat) -> UIFont {
        UIFont.systemFont(ofSize: size, weight: .bold)
    }

    public static func mono(_ size: CGFloat) -> UIFont {
        UIFont.monospacedSystemFont(ofSize: size, weight: .regular)
    }
}
