//
// SettingsViewController.swift
//
// Port of `SettingsFragment.java` / `settings_fragment.xml`. Exposes
// three left-aligned list rows in the same order as Android:
//
//   1. Networks         (push BlockchainNetworkViewController)
//   2. Advanced Signing (BinaryRadioDialog -> ADVANCED_SIGNING_ENABLED_KEY)
//   3. Backup           (BinaryRadioDialog -> BACKUP_ENABLED_KEY)
//
// Each row is a left-aligned title with a right chevron and a 0.5pt
// divider beneath it, matching `settings_fragment.xml` row layout.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/view/fragment/SettingsFragment.java
//   app/src/main/res/layout/settings_fragment.xml
//

import UIKit

public final class SettingsViewController: UIViewController, HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .innerFragment }

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground
        let L = Localization.shared

        // Back arrow row at the top - tap returns to whichever primary
        // tab the user was on the moment they entered Settings (main
        // dashboard or Wallets list), as captured by HomeViewController.
        let backBar = makeBackBar(action: #selector(tapBack))

        // "Settings" title at the top, mirroring Android
        // `textView_settings_title` (bold 20sp, leading-aligned).
        let title = UILabel()
        title.text = L.getSettingsByLangValues()
        title.font = Typography.boldTitle(20)
        title.textColor = UIColor(named: "colorCommon6") ?? .label

        // Horizontal rule directly under the title, mirroring Android
        // `settings_fragment.xml` where a 1dp `line_2_shape` divider
        // sits immediately below `textview_settings_langValues_settings`.
        let titleRule = makeRowDivider()

        let networks = makeListRow(title: L.getNetworksByLangValues(),
                                   action: #selector(openNetworks))
        let signing  = makeListRow(title: L.getAdvancedSigningOptionByLangValues(),
                                   action: #selector(openAdvancedSigning))
        // Final row carries no bottom divider, matching Android where
        // there is no `<View ... line_2_shape />` after the Backup button.
        let backup   = makeListRow(title: L.getBackupByLangValues(),
                                   action: #selector(openBackup),
                                   showBottomDivider: false)

        let stack = UIStackView(arrangedSubviews: [
            backBar, title, titleRule, networks, signing, backup
        ])
        stack.axis = .vertical
        stack.spacing = 0
        // Breathing room above and below the title rule so the line
        // sits visually centered between the title text and the first
        // tappable row.
        stack.setCustomSpacing(8, after: backBar)
        stack.setCustomSpacing(8, after: title)
        stack.setCustomSpacing(8, after: titleRule)
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16)
        ])

        // Apply alpha-dim press feedback to each tappable list row.
        view.installPressFeedbackRecursive()
    }

    @objc private func tapBack() {
        // Routes to either `showMain()` or `showWallets()` based on
        // the tab snapshot captured when Settings was opened.
        (parent as? HomeViewController)?.popFromSettings()
    }

    /// Tappable settings row: left-aligned UILabel, right chevron, 0.5pt
    /// divider beneath. Mirrors `settings_fragment.xml` row layout
    /// (`?attr/selectableItemBackground` ripple + `divider`).
    ///
    /// Pass `showBottomDivider: false` for the final row so the layout
    /// matches Android, which omits the trailing rule under the last
    /// tappable button.
    private func makeListRow(title: String,
                             action: Selector,
                             showBottomDivider: Bool = true) -> UIControl {
        let row = UIControl()
        row.translatesAutoresizingMaskIntoConstraints = false
        row.heightAnchor.constraint(equalToConstant: 48).isActive = true
        row.addTarget(self, action: action, for: .touchUpInside)

        let label = UILabel()
        label.text = title
        label.font = Typography.body(15)
        label.textColor = UIColor(named: "colorCommon6") ?? .label
        label.translatesAutoresizingMaskIntoConstraints = false

        let chevron = UIImageView(image: UIImage(systemName: "chevron.right"))
        chevron.tintColor = UIColor(named: "colorCommon4") ?? .secondaryLabel
        chevron.contentMode = .scaleAspectFit
        chevron.translatesAutoresizingMaskIntoConstraints = false

        [label, chevron].forEach { row.addSubview($0) }
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: row.leadingAnchor, constant: 4),
            label.centerYAnchor.constraint(equalTo: row.centerYAnchor),
            label.trailingAnchor.constraint(lessThanOrEqualTo: chevron.leadingAnchor, constant: -8),

            chevron.trailingAnchor.constraint(equalTo: row.trailingAnchor, constant: -4),
            chevron.centerYAnchor.constraint(equalTo: row.centerYAnchor),
            chevron.widthAnchor.constraint(equalToConstant: 12),
            chevron.heightAnchor.constraint(equalToConstant: 16)
        ])

        if showBottomDivider {
            let divider = UIView()
            divider.backgroundColor =
                (UIColor(named: "colorRectangleLine") ?? .separator).withAlphaComponent(0.4)
            divider.translatesAutoresizingMaskIntoConstraints = false
            row.addSubview(divider)
            NSLayoutConstraint.activate([
                divider.leadingAnchor.constraint(equalTo: row.leadingAnchor),
                divider.trailingAnchor.constraint(equalTo: row.trailingAnchor),
                divider.bottomAnchor.constraint(equalTo: row.bottomAnchor),
                divider.heightAnchor.constraint(equalToConstant: 0.5)
            ])
        }
        return row
    }

    /// 0.5pt-tall horizontal rule used between the title and the first
    /// tappable row. Same colour and alpha as the per-row dividers so
    /// every line on the screen reads as a single uniform separator.
    private func makeRowDivider() -> UIView {
        let v = UIView()
        v.backgroundColor =
            (UIColor(named: "colorRectangleLine") ?? .separator).withAlphaComponent(0.4)
        v.translatesAutoresizingMaskIntoConstraints = false
        v.heightAnchor.constraint(equalToConstant: 0.5).isActive = true
        return v
    }

    @objc private func openNetworks() {
        (parent as? HomeViewController)?.beginTransactionNow(BlockchainNetworkViewController())
    }

    /// Mirrors `SettingsFragment.java:123-168` advanced signing dialog:
    /// Enabled / Disabled radios + Cancel/OK, writing back to
    /// `ADVANCED_SIGNING_ENABLED_KEY`.
    @objc private func openAdvancedSigning() {
        let L = Localization.shared
        let dlg = BinaryRadioDialogViewController(
            title: L.getSigningByLangValues(),
            message: L.getAdvancedSigningDescriptionByLangValues(),
            initialEnabled: PrefConnect.shared.readBool(PrefKeys.ADVANCED_SIGNING_ENABLED_KEY)
        ) { enabled in
            PrefConnect.shared.writeBool(PrefKeys.ADVANCED_SIGNING_ENABLED_KEY, enabled)
        }
        present(dlg, animated: true)
    }

    /// Mirrors `SettingsFragment.java:170-216` backup dialog: same
    /// Enabled / Disabled radios writing back to `BACKUP_ENABLED_KEY`.
    /// This replaces the previous Wallets-screen routing (which was
    /// unrelated to backup and surfaced as a blank screen).
    @objc private func openBackup() {
        let L = Localization.shared
        let dlg = BinaryRadioDialogViewController(
            title: L.getBackupByLangValues(),
            message: L.getBackupDescriptionByLangValues(),
            initialEnabled: PrefConnect.shared.readBool(PrefKeys.BACKUP_ENABLED_KEY)
        ) { enabled in
            PrefConnect.shared.writeBool(PrefKeys.BACKUP_ENABLED_KEY, enabled)
        }
        present(dlg, animated: true)
    }
}
