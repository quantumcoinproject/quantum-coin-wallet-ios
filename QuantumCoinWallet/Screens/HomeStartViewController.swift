// HomeStartViewController.swift
// Port of `HomeStartFragment.java` / `home_start_fragment.xml`. Walks
// the user through `infoStep` and `quizStep` items from `en_us.json`.
// Wrong answers open a `MessageInformationDialogViewController`;
// correct answers show the safety-quiz alert then proceed.
// Layout target (mirrors home_start_fragment.xml):
// ScrollView
// White rounded "card" (10pt margins, 15pt corner radius)
// Step line: "Welcome, info N OF M" / "Safety Quiz N OF M"
// Divider (1pt, alpha 0.2, colorRectangleLine)
// Title: item["title"]
// Body: item["desc"] <- info phase
// item["question"] + radios <- quiz phase
// Divider (same)
// Right-aligned green "Next" pill button (#7d44aa, 16pt corners)
// Android reference:
// app/src/main/java/com/quantumcoinwallet/app/view/fragment/HomeStartFragment.java
// app/src/main/res/layout/home_start_fragment.xml
// app/src/main/res/drawable/button_green_shadow.xml

import UIKit

public final class HomeStartViewController: UIViewController, HomeScreenViewTypeProviding {

    public var screenViewType: ScreenViewType { .onboarding }
    public var onComplete: (() -> Void)?

    private enum Step { case info(Int); case quiz(Int) }

    private var infoItems: [[String: String]] = []
    private var quizItems: [[String: Any]] = []
    private var currentStep: Step = .info(0)

    // Scroll + card chrome
    private let scrollView = UIScrollView()
    private let cardView = UIView()
    private let cardStack = UIStackView()

    // Card content
    private let stepLabel = UILabel()
    private let topDivider = HomeStartViewController.makeDivider()
    private let titleLabel = UILabel()
    private let messageLabel = UILabel()
    private let radioStack = UIStackView()
    private let bottomDivider = HomeStartViewController.makeDivider()
    private let nextButton = GreenPillButton(type: .system)
    private let nextRow = UIStackView()

    private var selectedChoiceIndex: Int?

    // MARK: - Lifecycle

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear

        installScroll()
        installCard()

        infoItems = Localization.shared.getInfoList()
        quizItems = Localization.shared.getQuiz()

        render()

        // The Next pill button is built once in `installCard` and is
        // already in the hierarchy. Quiz `ChoiceRowButton` rows are
        // re-built per step inside `render` which now also installs
        // press feedback (idempotent for static surfaces).
        view.installPressFeedbackRecursive()
    }

    // MARK: - View setup

    private func installScroll() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.alwaysBounceVertical = true
        view.addSubview(scrollView)
        NSLayoutConstraint.activate([
                scrollView.topAnchor.constraint(equalTo: view.topAnchor),
                scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
                scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
            ])
    }

    private func installCard() {
        // White rounded card. `colorCommon7` is white in the Android theme.
        cardView.backgroundColor = UIColor(named: "colorCommon7") ?? .white
        cardView.layer.cornerRadius = 15
        // Unclipped so the inner Next / Done `GreenPillButton` drop
        // shadow can bleed past the card edge. The card's `cardStack`
        // is inset 20pt from every side, so no inner content visually
        // overlaps the rounded corners; only the shadow does.
        cardView.clipsToBounds = false
        cardView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.addSubview(cardView)

        // Card lays out its inner rows with a vertical stack. The
        // outer 10pt inset on the card matches the inner RelativeLayout
        // margins in the Android XML.
        cardStack.axis = .vertical
        cardStack.spacing = 0
        cardStack.alignment = .fill
        cardStack.translatesAutoresizingMaskIntoConstraints = false
        cardView.addSubview(cardStack)

        // 10pt left/right card margins from the screen, 16pt top/bottom
        // breathing room so the card doesn't kiss the banner / safe area.
        NSLayoutConstraint.activate([
                cardView.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor, constant: 16),
                cardView.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor, constant: 10),
                cardView.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor, constant: -10),
                cardView.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor, constant: -16),
                cardView.widthAnchor.constraint(equalTo: scrollView.frameLayoutGuide.widthAnchor, constant: -20),

                cardStack.topAnchor.constraint(equalTo: cardView.topAnchor, constant: 20),
                cardStack.leadingAnchor.constraint(equalTo: cardView.leadingAnchor, constant: 20),
                cardStack.trailingAnchor.constraint(equalTo: cardView.trailingAnchor, constant: -20),
                cardStack.bottomAnchor.constraint(equalTo: cardView.bottomAnchor, constant: -25)
            ])

        // Row content
        stepLabel.font = Typography.boldTitle(20)
        stepLabel.textColor = UIColor(named: "colorCommon6") ?? .black
        stepLabel.numberOfLines = 0

        titleLabel.font = Typography.boldTitle(20)
        titleLabel.textColor = UIColor(named: "colorCommon6") ?? .black
        titleLabel.numberOfLines = 0

        messageLabel.font = Typography.body(16)
        messageLabel.textColor = UIColor(named: "colorCommon6") ?? .black
        messageLabel.numberOfLines = 0

        radioStack.axis = .vertical
        radioStack.spacing = 2
        radioStack.alpha = 0.6 // matches Android RadioButton alpha 0.6

        // Right-align the Next button by putting it inside a horizontal
        // stack with a leading flexible spacer.
        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        nextRow.axis = .horizontal
        nextRow.alignment = .center
        nextRow.distribution = .fill
        nextRow.spacing = 0
        nextRow.addArrangedSubview(spacer)
        nextRow.addArrangedSubview(nextButton)

        nextButton.setTitle(Localization.shared.getNextByLangValues(), for: .normal)
        nextButton.addTarget(self, action: #selector(tapNext), for: .touchUpInside)
        nextButton.heightAnchor.constraint(equalToConstant: 43).isActive = true

        // Compose the card stack with explicit Android-style spacing
        // between rows. UIStackView's `spacing` is uniform, so we use
        // `setCustomSpacing(after:)` to mirror the per-row margins in
        // home_start_fragment.xml.
        cardStack.addArrangedSubview(stepLabel)
        cardStack.setCustomSpacing(20, after: stepLabel)
        cardStack.addArrangedSubview(topDivider)
        cardStack.setCustomSpacing(10, after: topDivider)
        cardStack.addArrangedSubview(titleLabel)
        cardStack.setCustomSpacing(10, after: titleLabel)
        cardStack.addArrangedSubview(messageLabel)
        cardStack.setCustomSpacing(10, after: messageLabel)
        cardStack.addArrangedSubview(radioStack)
        cardStack.setCustomSpacing(20, after: radioStack)
        cardStack.addArrangedSubview(bottomDivider)
        cardStack.setCustomSpacing(10, after: bottomDivider)
        cardStack.addArrangedSubview(nextRow)
    }

    private static func makeDivider() -> UIView {
        let v = UIView()
        v.backgroundColor = UIColor(named: "colorRectangleLine") ?? UIColor(white: 0.2, alpha: 1)
        v.alpha = 0.2
        v.translatesAutoresizingMaskIntoConstraints = false
        v.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return v
    }

    // MARK: - Render

    private func render() {
        // Clear quiz rows from previous step.
        radioStack.arrangedSubviews.forEach { $0.removeFromSuperview() }
        selectedChoiceIndex = nil

        switch currentStep {
            case .info(let i):
            let item = infoItems[safe: i] ?? [:]
            stepLabel.text = formatStep(
                template: Localization.shared.getInfoStep(),
                step: i + 1,
                total: infoItems.count)
            titleLabel.text = item["title"]
            // The JSON key is "desc" (matches JsonInteract.data_lang_key_desc),
            // not "description". Mismatch caused blank body labels.
            messageLabel.text = item["desc"]
            messageLabel.isHidden = (messageLabel.text?.isEmpty ?? true)
            radioStack.isHidden = true

            case .quiz(let i):
            let item = quizItems[safe: i] ?? [:]
            stepLabel.text = formatStep(
                template: Localization.shared.getQuizStep(),
                step: i + 1,
                total: quizItems.count)
            titleLabel.text = (item["title"] as? String) ?? ""
            messageLabel.text = (item["question"] as? String) ?? ""
            messageLabel.isHidden = false
            radioStack.isHidden = false

            // The JSON shape is `choices: [String]` plus a question-level
            // `correctChoice: Int`; the previous `[[String: Any]]` cast
            // collapsed to [] and rendered no rows.
            let choices = (item["choices"] as? [String]) ?? []
            for (index, text) in choices.enumerated() {
                let row = ChoiceRowButton()
                row.setTitle(text, for: .normal)
                row.tag = index
                row.addTarget(self, action: #selector(tapChoice(_:)), for: .touchUpInside)
                radioStack.addArrangedSubview(row)
            }
        }

        nextButton.setTitle(Localization.shared.getNextByLangValues(), for: .normal)

        // Press feedback for any newly-installed quiz `ChoiceRowButton`
        // rows. `enablePressFeedback` is idempotent for the static
        // controls (Next button) that were already wired in viewDidLoad.
        radioStack.installPressFeedbackRecursive()
    }

    /// Replace the `[STEP]` and `[TOTAL_STEPS]` placeholders used by
    /// `infoStep` / `quizStep` in `en_us.json`.
    private func formatStep(template: String, step: Int, total: Int) -> String {
        template
        .replacingOccurrences(of: "[STEP]", with: "\(step)")
        .replacingOccurrences(of: "[TOTAL_STEPS]", with: "\(total)")
    }

    // MARK: - Actions

    @objc private func tapChoice(_ sender: UIButton) {
        selectedChoiceIndex = sender.tag
        for case let row as ChoiceRowButton in radioStack.arrangedSubviews {
            row.isChecked = (row.tag == sender.tag)
        }
    }

    @objc private func tapNext() {
        switch currentStep {
            case .info(let i):
            if i + 1 < infoItems.count {
                currentStep = .info(i + 1)
            } else {
                currentStep = .quiz(0)
            }
            render()

            case .quiz(let i):
            guard let choice = selectedChoiceIndex else {
                // Android shows the same centered information dialog as
                // wrong-answer (`MessageInformationDialogFragment`) with
                // `quizNoChoice`. Mirroring that here puts the message
                // dead-center instead of as a top toast.
                let msg = MessageInformationDialogViewController(
                    title: "",
                    message: Localization.shared.getQuizNoChoice(),
                    icon: UIImage(systemName: "exclamationmark.circle.fill"),
                    iconTint: .systemOrange)
                present(msg, animated: true)
                return
            }
            let item = quizItems[safe: i] ?? [:]
            // Android stores `correctChoice` as 1-based (RadioButton tags
            // are 1..4). Compare against the 0-based selection + 1 so the
            // existing JSON works untouched.
            let correctChoice = (item["correctChoice"] as? Int) ?? -1
            let correct = (choice + 1) == correctChoice
            if correct {
                // Android `safety_quiz_alert_dialog_fragment.xml` shows a
                // 50dp `img_right` icon above the message. SF Symbol
                // checkmark.circle.fill is the system equivalent.
                let alert = ConfirmDialogViewController(
                    title: "",
                    message: (item["afterQuizInfo"] as? String) ?? "",
                    confirmText: Localization.shared.getOkByLangValues(),
                    hideCancel: true,
                    icon: UIImage(systemName: "checkmark.circle.fill"),
                    iconTint: .systemGreen)
                alert.onConfirm = { [weak self] in self?.advanceAfterCorrect() }
                present(alert, animated: true)
            } else {
                // Android `message_information_dialog_fragment.xml` uses
                // `img_information` for both wrong-answer and no-choice.
                let wrong = Localization.shared.getQuizWrongAnswer
                let msg = MessageInformationDialogViewController(
                    title: "",
                    message: wrong(),
                    icon: UIImage(systemName: "exclamationmark.circle.fill"),
                    iconTint: .systemOrange)
                present(msg, animated: true)
            }
        }
    }

    private func advanceAfterCorrect() {
        if case .quiz(let i) = currentStep {
            if i + 1 < quizItems.count {
                currentStep = .quiz(i + 1)
                render()
            } else {
                (parent as? HomeViewController)?.beginTransactionNow(HomeWalletViewController())
            }
        }
    }
}

// MARK: - ChoiceRowButton

/// Single radio-style row used in the quiz: leading circle / dot
/// indicator + multiline text. Mirrors the Android RadioButton shape.
/// Uses `type: .custom` (the default) - `.system` adds tint pulse +
/// highlight animation that visibly flashes the row + the surrounding
/// stack on selection.
private final class ChoiceRowButton: UIButton {

    var isChecked: Bool = false {
        didSet {
            // Wrap the title swap in `performWithoutAnimation` so the
            // intrinsic-size relayout doesn't ripple through the parent
            // UIStackView with an animated frame change.
            UIView.performWithoutAnimation {
                updateIndicator()
                layoutIfNeeded()
            }
        }
    }

    override init(frame: CGRect) {
        super.init(frame: frame)
        configure()
    }
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        configure()
    }

    private func configure() {
        contentHorizontalAlignment = .leading
        titleLabel?.font = Typography.body(16)
        setTitleColor(UIColor(named: "colorCommon6") ?? .black, for: .normal)
        contentEdgeInsets = UIEdgeInsets(top: 6, left: 8, bottom: 6, right: 8)
        titleEdgeInsets = UIEdgeInsets(top: 0, left: 8, bottom: 0, right: 0)
        titleLabel?.numberOfLines = 0
        adjustsImageWhenHighlighted = false
        // `.custom` already opts out of system tinting, but be explicit
        // about the pressed-state title color to match `.normal` so the
        // user's tap doesn't briefly recolor the row.
        setTitleColor(UIColor(named: "colorCommon6") ?? .black, for: .highlighted)
        updateIndicator()
    }

    private func updateIndicator() {
        // Filled vs. open circle character matches Android's RadioButton
        // selected/unselected state in a font-portable way.
        let symbol = isChecked ? "\u{25CF}" : "\u{25CB}" // ● / ○
        let title = (currentTitle ?? "")
        .replacingOccurrences(of: "\u{25CF} ", with: "")
        .replacingOccurrences(of: "\u{25CB} ", with: "")
        setTitle("\(symbol) \(title)", for: .normal)
    }

    override func setTitle(_ title: String?, for state: UIControl.State) {
        guard let t = title else { super.setTitle(nil, for: state); return }
        // Strip any pre-existing indicator so callers can pass plain text
        // and we always re-derive the symbol from `isChecked`.
        let cleaned = t
        .replacingOccurrences(of: "\u{25CF} ", with: "")
        .replacingOccurrences(of: "\u{25CB} ", with: "")
        let symbol = isChecked ? "\u{25CF}" : "\u{25CB}"
        super.setTitle("\(symbol) \(cleaned)", for: state)
    }
}

// MARK: -

fileprivate extension Array {
    subscript(safe i: Int) -> Element? { (i >= 0 && i < count) ? self[i] : nil }
}
