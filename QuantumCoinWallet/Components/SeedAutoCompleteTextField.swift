//
// SeedAutoCompleteTextField.swift
//
// BIP39 prefix-suggestion text field used by the seed-words verify and
// restore-from-seed screens. Mirrors Android's
// `AutoCompleteTextView` + `SeedWordAutoCompleteAdapter`:
//
//   - As the user types, suggestions are filtered from
//     `BIP39Words.all` by case-insensitive prefix.
//   - Up to `maxSuggestions` rows are shown in a small popup directly
//     below the field.
//   - Tapping a row replaces the field text with the suggestion
//     (uppercased to match Android's `textCapCharacters` input type)
//     and dismisses the popup.
//   - When the field resigns first responder the popup hides.
//
// The popup is hosted on the view's window so it floats above any
// surrounding UIScrollView clipping. It auto-tracks the field's frame
// while the field is editing.
//

import UIKit

@MainActor
public final class SeedAutoCompleteTextField: UITextField {

    // MARK: - Public

    /// Optional callback fired after the user picks a suggestion. The
    /// containing screen can use this to advance focus to the next
    /// field, the way Android's `setOnItemClickListener` does.
    public var onCommit: ((String) -> Void)?

    /// Maximum suggestion rows to render at once. 5 matches a comfortable
    /// dropdown height (~160pt) without overlapping the next chip row.
    public var maxSuggestions: Int = 5

    // MARK: - Private

    private var suggestions: [String] = []
    private weak var popup: UITableView?
    private weak var popupShadowContainer: UIView?
    private weak var popupBackdrop: UIView?

    // MARK: - Init

    public override init(frame: CGRect) {
        super.init(frame: frame)
        configure()
    }
    public required init?(coder: NSCoder) {
        super.init(coder: coder)
        configure()
    }

    private func configure() {
        autocapitalizationType = .allCharacters // mirrors Android textCapCharacters
        autocorrectionType = .no
        spellCheckingType = .no
        addTarget(self, action: #selector(textChanged), for: .editingChanged)
        addTarget(self, action: #selector(editingEnded), for: .editingDidEnd)
    }

    // MARK: - Filtering

    @objc private func textChanged() {
        let prefix = (text ?? "").trimmingCharacters(in: .whitespaces)
        suggestions = BIP39Words.suggestions(prefix: prefix, limit: maxSuggestions)
        refreshPopup()
    }

    @objc private func editingEnded() {
        // Keep the popup briefly so a tap on a suggestion is registered
        // before the field resigns. Hiding immediately would eat the tap.
        DispatchQueue.main.async { [weak self] in self?.hidePopup() }
    }

    // MARK: - Popup

    private func refreshPopup() {
        guard !suggestions.isEmpty,
              let window = window else {
            hidePopup()
            return
        }
        let table = ensurePopup(in: window)
        table.reloadData()
        positionPopup(table)
    }

    private func ensurePopup(in window: UIWindow) -> UITableView {
        if let existing = popup { return existing }
        // Backdrop captures taps outside the popup so it dismisses like
        // a real combo box. It is transparent and only catches touches.
        let backdrop = UIView()
        backdrop.backgroundColor = .clear
        backdrop.frame = window.bounds
        backdrop.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        backdrop.addGestureRecognizer(
            UITapGestureRecognizer(target: self, action: #selector(backdropTapped)))
        window.addSubview(backdrop)

        // Rounded-rect popup matching Android's M3 dropdown: 12pt
        // continuous corner. The shadow is hosted on an outer
        // container so the table itself can clipsToBounds for the
        // rounded mask without losing the shadow.
        let shadowContainer = UIView()
        shadowContainer.backgroundColor = .clear
        shadowContainer.layer.shadowColor = UIColor.black.cgColor
        shadowContainer.layer.shadowOpacity = 0.15
        shadowContainer.layer.shadowRadius = 4
        shadowContainer.layer.shadowOffset = CGSize(width: 0, height: 2)
        shadowContainer.layer.shouldRasterize = true
        shadowContainer.layer.rasterizationScale = UIScreen.main.scale

        let t = UITableView(frame: .zero, style: .plain)
        t.dataSource = self
        t.delegate = self
        t.separatorInset = .zero
        t.rowHeight = 32
        t.layer.cornerRadius = 12
        t.layer.cornerCurve = .continuous
        t.clipsToBounds = true
        t.layer.borderWidth = 1
        t.layer.borderColor = UIColor.separator.cgColor
        t.backgroundColor = UIColor(named: "colorBackgroundCard") ?? .systemBackground
        t.register(UITableViewCell.self, forCellReuseIdentifier: "cell")

        shadowContainer.addSubview(t)
        window.addSubview(shadowContainer)
        popup = t
        popupShadowContainer = shadowContainer
        popupBackdrop = backdrop
        return t
    }

    private func positionPopup(_ table: UITableView) {
        guard let window = window else { return }
        let frameInWindow = convert(bounds, to: window)
        let rows = max(1, min(suggestions.count, maxSuggestions))
        let height = CGFloat(rows) * table.rowHeight
        // Width: at least 140pt for short prefixes, but match the field
        // width when reasonable. Cap at 240 so very wide fields don't
        // produce an oversized dropdown.
        let width = min(max(frameInWindow.width, 140), 240)
        var origin = CGPoint(x: frameInWindow.minX,
                             y: frameInWindow.maxY + 2)
        if origin.x + width > window.bounds.maxX - 8 {
            origin.x = window.bounds.maxX - 8 - width
        }
        if origin.y + height > window.bounds.maxY - 8 {
            // Flip above the field if there isn't room below.
            origin.y = frameInWindow.minY - height - 2
        }
        let frame = CGRect(origin: origin,
                           size: CGSize(width: width, height: height))
        popupShadowContainer?.frame = frame
        table.frame = CGRect(origin: .zero, size: frame.size)
        // Backdrop sits behind the popup so the popup itself is tappable.
        popupBackdrop?.frame = window.bounds
        if let backdrop = popupBackdrop, let shadowContainer = popupShadowContainer {
            window.bringSubviewToFront(backdrop)
            window.bringSubviewToFront(shadowContainer)
        }
    }

    private func hidePopup() {
        popup?.removeFromSuperview()
        popup = nil
        popupShadowContainer?.removeFromSuperview()
        popupShadowContainer = nil
        popupBackdrop?.removeFromSuperview()
        popupBackdrop = nil
    }

    @objc private func backdropTapped() {
        hidePopup()
        resignFirstResponder()
    }

    public override func resignFirstResponder() -> Bool {
        let r = super.resignFirstResponder()
        hidePopup()
        return r
    }
}

extension SeedAutoCompleteTextField: UITableViewDataSource, UITableViewDelegate {
    public func tableView(_ tableView: UITableView,
                          numberOfRowsInSection section: Int) -> Int {
        suggestions.count
    }
    public func tableView(_ tableView: UITableView,
                          cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        cell.textLabel?.text = suggestions[indexPath.row].uppercased()
        cell.textLabel?.font = Typography.mono(13)
        cell.textLabel?.textColor = .label
        cell.backgroundColor = .systemBackground
        cell.selectionStyle = .default
        return cell
    }
    public func tableView(_ tableView: UITableView,
                          didSelectRowAt indexPath: IndexPath) {
        let chosen = suggestions[indexPath.row]
        text = chosen.uppercased()
        sendActions(for: .editingChanged)
        hidePopup()
        onCommit?(chosen.lowercased())
    }
}
