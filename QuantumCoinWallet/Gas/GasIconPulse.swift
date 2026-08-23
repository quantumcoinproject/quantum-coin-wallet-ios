// GasIconPulse.swift
// Desktop gas-pulse.svg animation (1.1 s loop: opacity 0.45 -> 1 ->
// 0.45, scale 1 -> 1.06 -> 1) applied to the pump while a gas estimate
// is in flight. Android reference: gas/GasIconPulse.java

import UIKit

public enum GasIconPulse {

    private static let animationKey = "gasPulse"
    private static let duration: CFTimeInterval = 1.1

    public static func start(_ icon: UIImageView) {
        stop(icon)
        icon.image = UIImage(named: "ic_gas_pulse")
        let alpha = CAKeyframeAnimation(keyPath: "opacity")
        alpha.values = [0.45, 1.0, 0.45]
        let scale = CAKeyframeAnimation(keyPath: "transform.scale")
        scale.values = [1.0, 1.06, 1.0]
        for a in [alpha, scale] {
            a.keyTimes = [0, 0.5, 1]
            a.timingFunction = CAMediaTimingFunction(name: .linear)
        }
        let group = CAAnimationGroup()
        group.animations = [alpha, scale]
        group.duration = duration
        group.repeatCount = .infinity
        group.isRemovedOnCompletion = false
        icon.layer.add(group, forKey: animationKey)
    }

    public static func stop(_ icon: UIImageView) {
        icon.layer.removeAnimation(forKey: animationKey)
        icon.alpha = 1
        icon.transform = .identity
        icon.image = UIImage(named: "ic_gas_outline")
    }
}
