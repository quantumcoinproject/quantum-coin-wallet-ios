// ShapeFactory.swift
// Programmatic equivalents of Android ShapeDrawables and selected
// LayerDrawables. See `ios_clone_spec` §3.4 for the full mapping
// strategy - this file covers the four shapes used most often across
// the screen layouts.
// Android reference:
// app/src/main/res/drawable/*.xml

import UIKit

public enum ShapeFactory {

    /// Rounded-rect filled view, analogous to
    /// `<shape android:shape="rectangle">` with `<corners>` + `<solid>`.
    public static func roundedRect(fill: UIColor, cornerRadius: CGFloat,
        stroke: UIColor? = nil, strokeWidth: CGFloat = 0) -> UIView {
        let v = UIView()
        v.backgroundColor = fill
        v.layer.cornerRadius = cornerRadius
        v.layer.masksToBounds = true
        if let stroke = stroke, strokeWidth > 0 {
            v.layer.borderColor = stroke.cgColor
            v.layer.borderWidth = strokeWidth
        }
        return v
    }

    /// Gradient banner used by `drawable-v24/gradient_layer.xml`.
    /// Caller installs this on a `UIView`'s layer hierarchy.
    public static func gradientLayer(topLeftColor: UIColor, topRightColor: UIColor,
        bottomLeftColor: UIColor, bottomRightColor: UIColor) -> CAGradientLayer {
        let layer = CAGradientLayer()
        layer.colors = [
            topLeftColor.cgColor,
            topRightColor.cgColor,
            bottomLeftColor.cgColor,
            bottomRightColor.cgColor
        ]
        layer.startPoint = CGPoint(x: 0, y: 0)
        layer.endPoint = CGPoint(x: 1, y: 1)
        return layer
    }

    /// Elevated button background. Android renders this as a layer-list
    /// of two rounded rects (shadow + fill).
    public static func raisedButton(fill: UIColor, cornerRadius: CGFloat) -> UIView {
        let v = UIView()
        v.backgroundColor = fill
        v.layer.cornerRadius = cornerRadius
        v.layer.shadowColor = UIColor.black.cgColor
        v.layer.shadowOpacity = 0.18
        v.layer.shadowRadius = 3
        v.layer.shadowOffset = CGSize(width: 0, height: 2)
        return v
    }

    /// Sweep-gradient indeterminate spinner used by Android's
    /// `drawable/progress.xml`. Returns a UIView that auto-rotates.
    public static func progressRing(color: UIColor, lineWidth: CGFloat = 3,
        diameter: CGFloat) -> UIView {
        let v = UIView(frame: CGRect(x: 0, y: 0, width: diameter, height: diameter))
        let layer = CAShapeLayer()
        let path = UIBezierPath(ovalIn: v.bounds.insetBy(dx: lineWidth/2, dy: lineWidth/2))
        layer.path = path.cgPath
        layer.strokeColor = color.cgColor
        layer.fillColor = UIColor.clear.cgColor
        layer.lineWidth = lineWidth
        layer.strokeStart = 0
        layer.strokeEnd = 0.25
        layer.lineCap = .round
        v.layer.addSublayer(layer)

        let rotation = CABasicAnimation(keyPath: "transform.rotation.z")
        rotation.fromValue = 0
        rotation.toValue = 2 * Double.pi
        rotation.duration = 1.0
        rotation.repeatCount = .infinity
        v.layer.add(rotation, forKey: "spin")
        return v
    }
}
