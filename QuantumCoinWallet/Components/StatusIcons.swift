// StatusIcons.swift
// Desktop checkmark-circle-outline / alert-outline ionicons rendered in
// code (Android ic_status_success.xml / ic_status_failed.xml), shown by
// the send-completed dialog once the transaction confirms / fails.

import UIKit

public enum StatusIcons {

    /// Outlined circle + check, theme green #34D399.
    public static func success(size: CGFloat = 30) -> UIImage {
        UIGraphicsImageRenderer(size: CGSize(width: size, height: size)).image { ctx in
            let c = ctx.cgContext
            let s = size / 512
            c.scaleBy(x: s, y: s)
            c.setStrokeColor(UIColor(rgbHex: 0x1AB664).cgColor)
            c.setLineWidth(32)
            c.setLineCap(.round)
            c.setLineJoin(.round)
            c.addEllipse(in: CGRect(x: 48, y: 48, width: 416, height: 416))
            c.strokePath()
            c.move(to: CGPoint(x: 352, y: 176))
            c.addLine(to: CGPoint(x: 217.6, y: 336))
            c.addLine(to: CGPoint(x: 160, y: 272))
            c.strokePath()
        }.withRenderingMode(.alwaysOriginal)
    }

    /// Exclamation bar + dot, failure red #FF5A64.
    public static func failed(size: CGFloat = 30) -> UIImage {
        UIGraphicsImageRenderer(size: CGSize(width: size, height: size)).image { ctx in
            let c = ctx.cgContext
            let s = size / 512
            c.scaleBy(x: s, y: s)
            let red = UIColor(rgbHex: 0xE20C0C)
            c.setStrokeColor(red.cgColor)
            c.setFillColor(red.cgColor)
            c.setLineWidth(40)
            c.setLineCap(.round)
            c.move(to: CGPoint(x: 256, y: 96))
            c.addLine(to: CGPoint(x: 256, y: 320))
            c.strokePath()
            c.fillEllipse(in: CGRect(x: 228, y: 356, width: 56, height: 56))
        }.withRenderingMode(.alwaysOriginal)
    }
}
