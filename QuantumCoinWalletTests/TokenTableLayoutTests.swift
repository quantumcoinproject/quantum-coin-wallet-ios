// TokenTableLayoutTests.swift
// Geometry of the `HomeMainViewController` token table.
//
// The table is a horizontally scrollable grid of design-width
// columns (symbol 60 | balance 200 | name 160 | contract 320, plus
// three 1pt dividers = 743pt). On a phone that total exceeds the
// screen, which is what makes the grid scroll sideways. On iPad the
// screen is far wider, and the columns MUST stretch to fill it -
// otherwise the card stops at 743pt and leaves a large dead strip
// to its right (the reported iPad regression).
//
// These tests pin both halves of that rule: the design width acts
// as a FLOOR on compact widths, and as a RATIO on regular widths.

import XCTest
@testable import QuantumCoinWallet

@MainActor
final class TokenTableLayoutTests: XCTestCase {

    /// symbol + balance + name + contract, without dividers.
    private let designColumnsWidth: CGFloat = 60 + 200 + 160 + 320
    /// Three 1pt dividers between the four columns.
    private let separatorTotal: CGFloat = 3
    /// `HomeMainViewController.cardInset`, applied on the leading and
    /// trailing edge of the horizontal scroller.
    private let cardInset: CGFloat = 16

    private var designTotalWidth: CGFloat { designColumnsWidth + separatorTotal }

    /// Lays the screen out at a fixed size and returns the outer
    /// horizontal scroller that hosts the table card.
    private func layOutHome(width: CGFloat, height: CGFloat) throws -> UIScrollView {
        let vc = HomeMainViewController()
        vc.view.frame = CGRect(x: 0, y: 0, width: width, height: height)
        vc.view.layoutIfNeeded()
        let scroller = try XCTUnwrap(
            vc.view.subviews.compactMap { $0 as? UIScrollView }.first,
            "Home main screen must host the token card in a horizontal scroll view.")
        return scroller
    }

    /// The header row: the only stack in the hierarchy holding four
    /// columns interleaved with three divider views.
    private func headerStack(in root: UIView) -> UIStackView? {
        if let stack = root as? UIStackView, stack.arrangedSubviews.count == 7 {
            return stack
        }
        for sub in root.subviews {
            if let hit = headerStack(in: sub) { return hit }
        }
        return nil
    }

    /// Column wrappers only - the odd indices are the 1pt dividers.
    private func columnWidths(in stack: UIStackView) -> [CGFloat] {
        stack.arrangedSubviews.enumerated()
            .filter { $0.offset % 2 == 0 }
            .map { $0.element.bounds.width }
    }

    /// iPad: the columns MUST consume the whole card, and MUST keep
    /// their design proportions while doing so. A regression that
    /// pinned the columns back to their design widths would leave
    /// `contentSize.width` at 743 with the rest of the screen blank.
    func testColumnsFillTheCardOnRegularWidth() throws {
        let width: CGFloat = 1366
        let scroller = try layOutHome(width: width, height: 1024)
        let available = width - 2 * cardInset

        XCTAssertEqual(
            scroller.contentSize.width, available, accuracy: 0.5,
            "On a regular-width screen the token table MUST span the "
            + "full width between the card insets, not stop at its "
            + "\(designTotalWidth)pt design width.")

        let stack = try XCTUnwrap(headerStack(in: scroller),
            "Header row (4 columns + 3 dividers) must be present.")
        let widths = columnWidths(in: stack)
        XCTAssertEqual(widths.count, 4)
        XCTAssertEqual(
            widths.reduce(0, +) + separatorTotal, available, accuracy: 0.5,
            "Columns plus dividers MUST add up to the card width "
            + "exactly - any shortfall is the dead strip this test "
            + "exists to catch, any excess overflows the card.")

        // Proportions are preserved: each column keeps its design
        // share of the stretched row.
        let stretched = available - separatorTotal
        for (w, design) in zip(widths, [60.0, 200.0, 160.0, 320.0] as [CGFloat]) {
            XCTAssertEqual(
                w, stretched * design / designColumnsWidth, accuracy: 0.5,
                "Surplus width MUST be shared in the design ratio.")
        }
    }

    /// iPhone: the design width is a floor, so the grid still
    /// overflows the screen and scrolls sideways. This is the half
    /// of the rule the iPad fix must not break - columns shrinking
    /// to fit a phone would truncate 18-decimal balances and
    /// contract addresses.
    func testTableKeepsDesignWidthAndScrollsOnCompactWidth() throws {
        let width: CGFloat = 390
        let scroller = try layOutHome(width: width, height: 844)

        XCTAssertEqual(
            scroller.contentSize.width, designTotalWidth, accuracy: 0.5,
            "On a compact screen the table MUST keep its full "
            + "\(designTotalWidth)pt design width so the columns stay "
            + "readable and the grid scrolls horizontally.")
        XCTAssertGreaterThan(
            scroller.contentSize.width, width - 2 * cardInset,
            "Content wider than the viewport is what makes the "
            + "column strip pannable on a phone.")

        let stack = try XCTUnwrap(headerStack(in: scroller))
        XCTAssertEqual(columnWidths(in: stack), [60, 200, 160, 320],
            "Compact layout MUST render the columns at their exact "
            + "design widths.")
    }
}
