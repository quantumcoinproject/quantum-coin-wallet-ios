// WalletIcon.swift
// Wallet outline (card body + strap flap + clasp dot), the same glyph
// as the QuantumSwap burger menu / Android ic_wallet_outline.xml.
// Rendered as a template image so it tints with colorCommon6
// (black in light mode, white in dark mode).

import UIKit

public enum WalletIcon {
    public static func image(size: CGFloat = 22) -> UIImage {
        UIGraphicsImageRenderer(size: CGSize(width: size, height: size)).image { ctx in
            let c = ctx.cgContext
            let s = size / 512
            c.scaleBy(x: s, y: s)
            c.setStrokeColor(UIColor.black.cgColor)
            c.setFillColor(UIColor.black.cgColor)
            c.setLineWidth(32)
            c.setLineJoin(.round)
            // Card body.
            c.addPath(UIBezierPath(roundedRect: CGRect(x: 48, y: 144, width: 416, height: 288),
                                   cornerRadius: 48).cgPath)
            c.strokePath()
            // Strap flap.
            let flap = UIBezierPath()
            flap.move(to: CGPoint(x: 411.36, y: 144))
            flap.addLine(to: CGPoint(x: 411.36, y: 114))
            flap.addArc(withCenter: CGPoint(x: 361.36, y: 114), radius: 50,
                        startAngle: 0, endAngle: -CGFloat.pi / 2 - 0.17, clockwise: false)
            flap.addLine(to: CGPoint(x: 88.64, y: 109.85))
            flap.addArc(withCenter: CGPoint(x: 98, y: 159), radius: 50,
                        startAngle: -CGFloat.pi / 2 - 0.19, endAngle: CGFloat.pi, clockwise: false)
            flap.addLine(to: CGPoint(x: 48, y: 208))
            c.addPath(flap.cgPath)
            c.strokePath()
            // Clasp dot.
            c.fillEllipse(in: CGRect(x: 336, y: 256, width: 64, height: 64))
        }.withRenderingMode(.alwaysTemplate)
    }
}
